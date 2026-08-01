package writeback

// The namespace lane's pre-lock admission contract (metadatacredit.go).
//
// Before it, a delegated mkdir/create/rename/unlink/truncate/xattr that found
// the metadata lane momentarily full got ErrUplinkStalled on the spot — an
// instant, fatal EIO produced inside e.mu without consulting the flusher's
// watchdog, on a mount whose uplink was making durable progress the whole time.
// An application cannot act on that: the store is not full, the far end is not
// dead, and the very same operation is admissible one authority advance later.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// pinSegmentTarget compresses the rotation threshold so a fixture-scale cap
// spans several segments. Reclamation is per-segment and never touches the
// ACTIVE one, so a cap that fits inside a single segment can never be relieved
// — a property of the fixture's proportions, not of the gate. Production runs a
// 512 MiB cap over 64 MiB segments.
func pinSegmentTarget(t *testing.T, n int64) {
	t.Helper()
	old := segmentTargetBytes
	segmentTargetBytes = n
	t.Cleanup(func() { segmentTargetBytes = old })
}

// TestMetadataAdmissionWaitsForProgressInsteadOfFailing is the finding itself.
//
// The lane is filled with the uplink gated shut, so the next namespace mutation
// cannot be admitted. The pre-lock gate must NOT answer instantly: it must park
// — holding nothing — until the authority applies the backlog, and then admit.
// A gate that returns an error while the uplink is healthy has invented a
// verdict the watchdog never issued.
func TestMetadataAdmissionWaitsForProgressInsteadOfFailing(t *testing.T) {
	pinSegmentTarget(t, 512<<10)
	f := newSaturationFixture(t, 4<<20)
	if err := fillMetadataLane(t, f); err == nil {
		t.Fatal("the metadata lane never refused an append")
	}
	if !f.e.MetadataLaneFull() {
		t.Fatal("the lane refused an append but does not report itself full")
	}

	admitted := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		admitted <- f.e.AdmitMetadataMutation(ctx)
	}()

	// While the uplink is shut the gate must still be waiting: an answer here is
	// the instant refusal this contract removes.
	select {
	case err := <-admitted:
		t.Fatalf("pre-lock metadata admission answered %v while the lane was full and "+
			"the uplink had made no progress; it must pace on applied progress, not "+
			"refuse", err)
	case <-time.After(250 * time.Millisecond):
	}

	// The one event that frees metadata bytes.
	f.openUplink()

	select {
	case err := <-admitted:
		if err != nil {
			t.Fatalf("metadata admission after the uplink drained = %v, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("metadata admission never completed after the uplink drained")
	}

	// And the mutation it gates now succeeds, on the same mount, with no retry
	// visible to any application.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, _, err := f.e.Mkdir(ctx, "d/after-backpressure", 0o755); err != nil {
		t.Fatalf("mkdir after admission: %v", err)
	}
}

// TestMetadataAdmissionHoldsNoEngineLockWhileItWaits proves the placement, not
// just the behaviour. A gate that waits under e.mu would be the namespace
// lane's drain dependency all over again: every lookup, every read, every
// delegation recall would queue behind it.
func TestMetadataAdmissionHoldsNoEngineLockWhileItWaits(t *testing.T) {
	f := newSaturationFixture(t, 4<<20)
	if err := fillMetadataLane(t, f); err == nil {
		t.Fatal("the metadata lane never refused an append")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waiting := make(chan struct{})
	go func() {
		close(waiting)
		_ = f.e.AdmitMetadataMutation(ctx)
	}()
	<-waiting
	time.Sleep(100 * time.Millisecond)

	// Everything that needs e.mu must still run to completion with the gate
	// parked.
	promptly(t, 2*time.Second, "a lookup with a namespace mutation parked in admission", func() {
		f.e.lookup("d")
	})
	promptly(t, 2*time.Second, "a status read with a namespace mutation parked in admission", func() {
		_ = f.e.Status()
	})
	cancel()
	f.openUplink()
}

// TestMetadataAdmissionReportsOnlyTheWatchdogsStall is the split the whole
// design rests on. ErrUplinkStalled is the engine's ONE stall verdict; a
// frontend or a gate that derives it from elapsed time reports a dead far end
// for a link the engine considers healthy.
func TestMetadataAdmissionReportsOnlyTheWatchdogsStall(t *testing.T) {
	f := newSaturationFixture(t, 4<<20)
	if err := fillMetadataLane(t, f); err == nil {
		t.Fatal("the metadata lane never refused an append")
	}
	// The uplink is shut but the watchdog has not declared a stall yet, so the
	// gate must not produce one. Give it several credit-wait caps' worth of
	// chances by asking with a short deadline: the answer must be the CALLER'S
	// deadline, never a synthesized stall.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := f.e.AdmitMetadataMutation(ctx)
	if errors.Is(err, ErrUplinkStalled) {
		t.Fatalf("the gate synthesized a stall verdict (%v) the watchdog had not issued", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("metadata admission under a short caller deadline = %v, want the caller's "+
			"own deadline", err)
	}
	f.openUplink()
}

// TestMetadataAdmissionNeverSynthesizesENOSPC keeps ENOSPC where it can be
// decided exactly. The gate does not know the operation's size — the records are
// encoded later, under e.mu — so a gate that answered ENOSPC from its own
// worst-case demand would tell an application to delete files because a
// hypothetical maximum frame would not have fit. On a cap far smaller than one
// maximum frame the gate must still admit, and the exact reservation must own
// the definite refusal.
func TestMetadataAdmissionNeverSynthesizesENOSPC(t *testing.T) {
	f := newSaturationFixture(t, 64<<10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := f.e.AdmitMetadataMutation(ctx); err != nil {
		t.Fatalf("metadata admission on a cap smaller than one maximum frame = %v, "+
			"want nil: the gate must not decide a question only the exact "+
			"reservation can answer", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the gate waited %s on a demand no drain could ever satisfy", elapsed)
	}
	// A small mutation is admitted and works.
	if _, _, err := f.e.Mkdir(ctx, "d/small", 0o755); err != nil {
		t.Fatalf("mkdir on a small cap: %v", err)
	}
	// The definite refusal still comes from the exact reservation
	// (TestOversizedMetadataAppendKeepsDefiniteENOSPC covers the errno itself).
}

// TestMetadataAdmissionBudgetExceedsTheWatchdogWindow keeps the sizing
// relationship the namespace lane's budget is chosen for: it must strictly
// exceed the watchdog's verdict window plus one acquisition wait, so that on a
// link which made no progress at all the verdict is AVAILABLE before the budget
// runs out.
//
// It is deliberately no longer stated as a proof that expiry implies a verdict.
// It does not: flusher.advance resets lastProgress on every advance, so a late
// advance pushes the earliest possible declaration well past this budget. What
// makes the outcome definite is that both gates consult the LIVE verdict
// (Engine.StallVerdict) at expiry rather than inferring one from the arithmetic
// — see stallpolicy_test.go.
func TestMetadataAdmissionBudgetExceedsTheWatchdogWindow(t *testing.T) {
	if got, want := MetadataAdmissionBudget(), NoProgressWindow()+CreditWaitCap(); got <= want {
		t.Fatalf("metadataAdmissionBudget = %s, must strictly exceed "+
			"noProgressWindow + creditWaitCap = %s", got, want)
	}
}

// TestMetadataLaneFullIsFalseOnAHealthyStream guards the hot path: the gate is
// meant to be rare by construction (the metadata reserve is 64 MiB and one
// namespace mutation is a few hundred bytes), so an ordinary mount must never
// see it.
func TestMetadataLaneFullIsFalseOnAHealthyStream(t *testing.T) {
	f := newSaturationFixture(t, 4<<20)
	f.openUplink()
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		if _, _, err := f.e.Mkdir(ctx, "d/"+strings.Repeat("x", 8)+itoa(i), 0o755); err != nil {
			t.Fatalf("mkdir %d: %v", i, err)
		}
	}
	if f.e.MetadataLaneFull() {
		t.Fatal("a healthy stream reports the metadata lane full; the gate would pace " +
			"latency-critical namespace operations for no reason")
	}
	if err := f.e.AdmitMetadataMutation(ctx); err != nil {
		t.Fatalf("metadata admission on a healthy stream = %v, want nil", err)
	}
}
