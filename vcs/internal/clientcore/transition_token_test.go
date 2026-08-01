package clientcore

// The transition-token contract (mutationadmit.go) and the single operation
// deadline it is installed under.
//
// FINDING 1. The pre-lock classifier used to RELEASE without holding the
// delegation transition claim. That left a window the auditor's interleaving
// walks straight through: writer A's pre-lock ReleaseFor finds nothing to
// release and resolves the authority lane; writer B wins the acquire transition
// and installs a grant; A — now inside a.nsMu.RLock and its handle lock —
// reaches beginAuthorityMutation, WAITS for B's claim (an authority round trip)
// and then DRAINS B's fresh grant, all under the frontend's locks. Go's RWMutex
// is writer-preferring, so the next rename, remove or reclaim parks behind that
// wait and every lookup behind it.
//
// The fix is the token: the claim is taken before the release and held through
// the locked mutation, so no acquisition can install in that window and the
// locked region is a pure check.
//
// FINDING 2. Each stage used to carry its own budget, and budgets compose: a
// 40s credit stage could expire and then start a fresh, unbounded release. One
// absolute deadline now covers classification, credit, release and the
// authority RPC together.

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestClassifiedAuthorityWriteExcludesAcquisitionThroughTheLockedMutation is
// finding 1's interleaving, run deterministically.
func TestClassifiedAuthorityWriteExcludesAcquisitionThroughTheLockedMutation(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	watchInvalidationsForTest(t, v)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if _, st := v.Create(ctx, "d/seed", 0o644); st != fsproto.OK {
		t.Fatalf("delegated seed create: %d", st)
	}
	if !v.wb.Covers("d/seed") {
		t.Fatal("seed create did not install the prerequisite delegation")
	}

	// Writer A classifies its lane BEFORE any frontend lock. forceAuthority is
	// the unwind's terminator and the shape the auditor's interleaving starts
	// from.
	opCtx, granted, settle, err := v.AdmitWrite(ctx, "d/f", nil, 4096, true)
	if err != nil {
		t.Fatalf("pre-lock write classification: %v", err)
	}
	defer settle()
	if granted != 4096 {
		t.Fatalf("authority-lane grant = %d, want the whole request", granted)
	}
	if writeback.LaneOf(opCtx) != writeback.LaneAuthority {
		t.Fatalf("classified lane = %v, want LaneAuthority", writeback.LaneOf(opCtx))
	}
	if v.wb.Covers("d/seed") {
		t.Fatal("the authority lane was resolved without releasing the covering " +
			"delegation; the release would then have to happen under the frontend locks")
	}

	// Writer B now tries to acquire an overlapping grant. While A holds its
	// token this MUST NOT complete: an acquisition that installed here is
	// exactly the grant A would have had to wait for and then drain from inside
	// its namespace and handle locks.
	acquired := make(chan Status, 1)
	go func() {
		_, st := v.Create(ctx, "d/concurrent", 0o644)
		acquired <- st
	}()
	select {
	case st := <-acquired:
		t.Fatalf("an overlapping delegation acquisition completed (status %d) while a "+
			"classified authority write held its transition token; that grant is what "+
			"the write would drain under a.nsMu", st)
	case <-time.After(200 * time.Millisecond):
	}

	// A is now "inside the locks". beginAuthorityMutation must be a pure CHECK:
	// it may not begin a claim, may not wait for B, and may not release.
	checked := make(chan error, 1)
	go func() {
		_, end, berr := v.beginAuthorityMutation(opCtx, nil, "d/f")
		if end != nil {
			end()
		}
		checked <- berr
	}()
	select {
	case berr := <-checked:
		if berr != nil {
			t.Fatalf("the locked-region check failed: %v", berr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("beginAuthorityMutation BLOCKED inside the frontend's locks: it is " +
			"waiting for the acquisition its classifier was supposed to have excluded")
	}

	// Handing the token back is what lets the acquisition proceed.
	settle()
	select {
	case st := <-acquired:
		if st != fsproto.OK {
			t.Fatalf("the acquisition released by settle failed: %d", st)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the acquisition never completed after the token was handed back")
	}
}

// TestClassifiedNamespaceMutationExcludesAcquisitionThroughTheLockedMutation is
// the same contract for the NAMESPACE lane. It is what makes the lock order
// global: as long as metadata mutations took a.nsMu and THEN the claim, a write
// could not hold its claim across a.nsMu without closing a cycle.
func TestClassifiedNamespaceMutationExcludesAcquisitionThroughTheLockedMutation(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	watchInvalidationsForTest(t, v)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if _, st := v.Create(ctx, "d/seed", 0o644); st != fsproto.OK {
		t.Fatalf("delegated seed create: %d", st)
	}

	opCtx, settle, err := v.AdmitMutation(ctx, MutationIntent{Kind: MutationOther}, nil, true, "d/target")
	if err != nil {
		t.Fatalf("pre-lock namespace classification: %v", err)
	}
	defer settle()
	if writeback.LaneOf(opCtx) != writeback.LaneAuthority {
		t.Fatalf("classified lane = %v, want LaneAuthority", writeback.LaneOf(opCtx))
	}
	if v.wb.Covers("d/seed") {
		t.Fatal("the namespace classifier resolved the authority lane without releasing " +
			"the covering delegation")
	}

	acquired := make(chan Status, 1)
	go func() {
		_, st := v.Create(ctx, "d/concurrent", 0o644)
		acquired <- st
	}()
	select {
	case st := <-acquired:
		t.Fatalf("an overlapping acquisition completed (status %d) while a classified "+
			"namespace mutation held its transition token", st)
	case <-time.After(200 * time.Millisecond):
	}

	checked := make(chan error, 1)
	go func() {
		_, end, berr := v.beginAuthorityMutation(opCtx, nil, "d/target")
		if end != nil {
			end()
		}
		checked <- berr
	}()
	select {
	case berr := <-checked:
		if berr != nil {
			t.Fatalf("the locked-region check failed: %v", berr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("beginAuthorityMutation BLOCKED inside the frontend's locks")
	}
	settle()
	select {
	case <-acquired:
	case <-time.After(30 * time.Second):
		t.Fatal("the acquisition never completed after the token was handed back")
	}
}

// TestUncoveredOperandUnwindsInsteadOfTransitioning is the token's other half.
// An operand the classifier never saw is not protected by its release, so the
// locked region must UNWIND rather than release it there.
func TestUncoveredOperandUnwindsInsteadOfTransitioning(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opCtx, settle, err := v.AdmitMutation(ctx, MutationIntent{Kind: MutationOther}, nil, true, "d/claimed")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	defer settle()

	_, _, berr := v.beginAuthorityMutation(opCtx, nil, "elsewhere/unclaimed")
	if berr == nil {
		t.Fatal("an operand outside the token's claim was accepted inside the frontend " +
			"locks; nothing released it and nothing excludes an acquisition over it")
	}
	if st := statusErr(berr); !LaneChanged(st) {
		t.Fatalf("uncovered operand = %v (status %d), want the ErrLaneChanged unwind",
			berr, st)
	}
}

// TestOperationDeadlineIsOneAbsoluteBound is finding 2's arithmetic, as a test
// rather than a comment. Per-stage budgets compose; this one does not.
func TestOperationDeadlineIsOneAbsoluteBound(t *testing.T) {
	watchdog := writeback.NoProgressWindow() + writeback.CreditWaitCap()
	if creditAdmissionBudget <= watchdog {
		t.Fatalf("creditAdmissionBudget = %s must strictly exceed "+
			"noProgressWindow + creditWaitCap = %s, or the credit stage could expire "+
			"before the engine has a stall verdict and the frontend would have to "+
			"invent one", creditAdmissionBudget, watchdog)
	}
	if operationAdmissionBudget <= creditAdmissionBudget {
		t.Fatalf("operationAdmissionBudget = %s must strictly exceed "+
			"creditAdmissionBudget = %s: the authority-lane diversion the credit stage's "+
			"expiry produces must have room to run inside the SAME bound",
			operationAdmissionBudget, creditAdmissionBudget)
	}
	if operationAdmissionBudget >= volumeBarrierTimeout {
		t.Fatalf("operationAdmissionBudget = %s must land inside volumeBarrierTimeout "+
			"= %s, the bound a concurrent fsync/unmount drain is already running under",
			operationAdmissionBudget, volumeBarrierTimeout)
	}
}

// TestOperationDeadlineCoversTheWholeAdmissionAndExecution proves the bound is
// actually installed on the context the operation runs under — not just on the
// admission call — so the release and the authority RPC inherit it.
func TestOperationDeadlineCoversTheWholeAdmissionAndExecution(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	ctx := context.Background()

	before := time.Now()
	opCtx, _, settle, err := v.AdmitWrite(ctx, "d/f", nil, 4096, true)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	defer settle()
	deadline, ok := opCtx.Deadline()
	if !ok {
		t.Fatal("the classified operation carries NO deadline; the release and the " +
			"authority RPC that follow it are then unbounded")
	}
	if got := deadline.Sub(before); got > operationAdmissionBudget+time.Second {
		t.Fatalf("operation deadline is %s out, want at most operationAdmissionBudget "+
			"(%s)", got, operationAdmissionBudget)
	}

	// The unwind's second pass must not extend it: a bound that resets on every
	// pass is not a bound on the operation.
	secondCtx, cancel := WithOperationDeadline(opCtx)
	defer cancel()
	second, ok := secondCtx.Deadline()
	if !ok {
		t.Fatal("re-classification dropped the operation deadline")
	}
	if second.After(deadline) {
		t.Fatalf("re-classification extended the operation deadline from %s to %s; the "+
			"unwind loop would then have no bound at all", deadline, second)
	}
}
