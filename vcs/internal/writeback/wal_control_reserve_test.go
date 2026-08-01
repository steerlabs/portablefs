package writeback

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// fillToBudgetEpsilon drives the mutation lane to the last byte the budget will
// give it: coarse 4 KiB records first, then progressively smaller ones until
// even an empty record is refused. Every test in this file starts from that
// state — the interesting question is what a CONTROL frame does to a log the
// mutation lane has already taken to its bound.
func fillToBudgetEpsilon(t *testing.T, w *streamWAL, budget int64) int64 {
	t.Helper()
	admit := func(size int) error {
		_, err := w.appendMutationsWithin([][]byte{make([]byte, size)}, budget)
		return err
	}
	for size := 4 << 10; ; {
		err := admit(size)
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrNoSpace) {
			t.Fatalf("fill at %d-byte records: %v", size, err)
		}
		if size == 0 {
			break
		}
		size /= 2
	}
	used := w.DiskBytes()
	if used > budget {
		t.Fatalf("the mutation lane alone drove the log to %d bytes, past its %d budget", used, budget)
	}
	return used
}

func newControlReserveWAL(t *testing.T) *streamWAL {
	t.Helper()
	w, err := createStreamWAL(t.TempDir(), [16]byte{7}, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create stream: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// TestControlFramesStayInsideTheHardCap is the cap's actual claim: DiskBytes
// never exceeds BudgetBytes. Each subtest takes the mutation lane to the bound
// and then emits ONE control operation — a grant install, the APPLIED
// certificate CheckpointAndReclaim writes, a drained release — the paths that
// write PFW5 bytes without ever consulting the budget.
func TestControlFramesStayInsideTheHardCap(t *testing.T) {
	const budget = 256 << 10
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 32 << 10
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	t.Run("delegation install", func(t *testing.T) {
		w := newControlReserveWAL(t)
		if err := w.appendControlWithin(frameDelegation,
			delegationFrame{Scope: "d", Epoch: "e1"}, budget); err != nil {
			t.Fatalf("install first grant: %v", err)
		}
		fillToBudgetEpsilon(t, w, budget)
		// A second scope is the unbounded direction: it raises the re-emit cost
		// of every later rotation. It is the ONE thing that may be refused.
		err := w.appendControlWithin(frameDelegation,
			delegationFrame{Scope: "e", Epoch: "e2"}, budget)
		if err != nil && !errors.Is(err, ErrNoSpace) {
			t.Fatalf("install second grant at the bound: %v", err)
		}
		if got := w.DiskBytes(); got > budget {
			t.Fatalf("a DELEGATION frame at the bound left the log at %d bytes, past its %d cap", got, budget)
		}
	})

	t.Run("applied certificate", func(t *testing.T) {
		w := newControlReserveWAL(t)
		if err := w.appendControlWithin(frameDelegation,
			delegationFrame{Scope: "d", Epoch: "e1"}, budget); err != nil {
			t.Fatalf("install grant: %v", err)
		}
		fillToBudgetEpsilon(t, w, budget)
		// The frame CheckpointAndReclaim appends on EVERY authority advance,
		// through the same appendControlLocked path.
		if err := w.appendControl(frameApplied, appliedFrame{
			Through: w.LastSeq(), Digest: fmt.Sprintf("%x", w.Digest()),
		}); err != nil {
			t.Fatalf("APPLIED at the bound was refused: %v", err)
		}
		if got := w.DiskBytes(); got > budget {
			t.Fatalf("an APPLIED frame at the bound left the log at %d bytes, past its %d cap", got, budget)
		}
	})

	t.Run("drained release", func(t *testing.T) {
		w := newControlReserveWAL(t)
		if err := w.appendControlWithin(frameDelegation,
			delegationFrame{Scope: "d", Epoch: "e1"}, budget); err != nil {
			t.Fatalf("install grant: %v", err)
		}
		fillToBudgetEpsilon(t, w, budget)
		// APPLIED + RELEASE for a grant that is already live must NEVER be
		// refused, and must still fit.
		if err := w.recordDrainedRelease("d", "e1", w.LastSeq(), w.Digest()); err != nil {
			t.Fatalf("drained release at the bound was refused: %v", err)
		}
		if got := w.DiskBytes(); got > budget {
			t.Fatalf("APPLIED+RELEASE at the bound left the log at %d bytes, past its %d cap", got, budget)
		}
	})
}

// TestReclamationCheckpointNeverGrowsTheLog pins the property that lets the
// control reserve hold ONE checkpoint term rather than one per authority
// advance: the APPLIED certificate is charged to the space its own reclamation
// frees, so a checkpoint either shrinks the footprint or writes nothing.
func TestReclamationCheckpointNeverGrowsTheLog(t *testing.T) {
	const budget = 256 << 10
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 32 << 10
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	w := newControlReserveWAL(t)
	if err := w.appendControlWithin(frameDelegation,
		delegationFrame{Scope: "d", Epoch: "e1"}, budget); err != nil {
		t.Fatalf("install grant: %v", err)
	}
	fillToBudgetEpsilon(t, w, budget)

	// Nothing is applied, so nothing is reclaimable and nothing may be written.
	before := w.DiskBytes()
	if err := w.CheckpointAndReclaim(0, digestZero(), func(uint64) bool { return false }); err != nil {
		t.Fatalf("checkpoint with nothing reclaimable: %v", err)
	}
	if got := w.DiskBytes(); got != before {
		t.Fatalf("a checkpoint that reclaimed nothing grew the log from %d to %d bytes", before, got)
	}
	// Everything is applied and unpinned: the checkpoint pays for its
	// certificate out of the segments it retires.
	if err := w.CheckpointAndReclaim(w.LastSeq(), w.Digest(), func(uint64) bool { return false }); err != nil {
		t.Fatalf("checkpoint at the bound: %v", err)
	}
	if got := w.DiskBytes(); got > before {
		t.Fatalf("a reclaiming checkpoint grew the log from %d to %d bytes", before, got)
	}
	if got := w.DiskBytes(); got > budget {
		t.Fatalf("a reclamation checkpoint at the bound left the log at %d bytes, past its %d cap", got, budget)
	}
}

// TestGrantReleaseCyclesStayBounded is the unbounded-growth shape. The uplink
// never advances, so nothing is ever reclaimable; a workload that touches a
// scope about once a second grants and releases it forever. Each cycle writes
// DELEGATION + APPLIED + RELEASE. If those bytes bypass the budget the log
// grows without limit for as long as the mount lives.
func TestGrantReleaseCyclesStayBounded(t *testing.T) {
	const budget = 256 << 10
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 32 << 10
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	w := newControlReserveWAL(t)
	fillToBudgetEpsilon(t, w, budget)

	for cycle := 0; cycle < 4096; cycle++ {
		scope := "d" + strconv.Itoa(cycle)
		err := w.appendControlWithin(frameDelegation,
			delegationFrame{Scope: scope, Epoch: "e"}, budget)
		if errors.Is(err, ErrNoSpace) {
			// A refused grant is the definite answer: the mutation takes the
			// authority lane. Nothing was written, so the cycle ends here.
			continue
		}
		if err != nil {
			t.Fatalf("cycle %d install: %v", cycle, err)
		}
		if err := w.recordDrainedRelease(scope, "e", w.LastSeq(), w.Digest()); err != nil {
			t.Fatalf("cycle %d release: %v", cycle, err)
		}
		if got := w.DiskBytes(); got > budget {
			t.Fatalf("grant/release cycle %d drove the log to %d bytes, past its %d cap",
				cycle, got, budget)
		}
	}
}

// TestControlFrameRotationAtBudgetEpsilonStaysInsideTheCap pins the rollover
// term. A control frame can trip a segment rotation, and a rotation writes a
// 4096-byte header plus the WHOLE live-delegation set into the new segment
// before anything else may use it.
func TestControlFrameRotationAtBudgetEpsilonStaysInsideTheCap(t *testing.T) {
	const budget = 512 << 10
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 64 << 10
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	w := newControlReserveWAL(t)
	live := 0
	for i := 0; i < 32; i++ {
		err := w.appendControlWithin(frameDelegation,
			delegationFrame{Scope: "scope-" + strconv.Itoa(i), Epoch: "epoch-" + strconv.Itoa(i)}, budget)
		if errors.Is(err, ErrNoSpace) {
			break
		}
		if err != nil {
			t.Fatalf("install grant %d: %v", i, err)
		}
		live++
	}
	if live == 0 {
		t.Fatal("no grant could be installed at all")
	}
	fillToBudgetEpsilon(t, w, budget)

	// Put the active segment exactly at its rotation threshold without
	// fabricating a byte, then emit a control frame: it pays a 4096-byte header
	// plus the re-emit of the WHOLE live set before its own frames.
	w.mu.Lock()
	segmentTargetBytes = w.segments[len(w.segments)-1].size
	segments := len(w.segments)
	w.mu.Unlock()
	if err := w.recordDrainedRelease("scope-0", "epoch-0", w.LastSeq(), w.Digest()); err != nil {
		t.Fatalf("rotation-tripping control frame was refused: %v", err)
	}
	// The new segment must hold more than its bare header: that surplus is the
	// re-emitted live set plus the release pair.
	w.mu.Lock()
	rotated := len(w.segments) > segments
	surplus := w.segments[len(w.segments)-1].size - segmentHeaderSize
	w.mu.Unlock()
	if !rotated || surplus <= frameLen(maxAppliedPayload) {
		t.Fatalf("fixture did not exercise a re-emitting rotation (rotated=%v, surplus=%d bytes)", rotated, surplus)
	}
	if got := w.DiskBytes(); got > budget {
		t.Fatalf("a control frame's rotation left the log at %d bytes, past its %d cap", got, budget)
	}
}

// TestOversizedControlFieldsAreRefusedAtWriteTime closes the latent corruption:
// the decoder rejects ANY frame whose payload exceeds maxMutationPayload, but
// the control write paths never checked. An unbounded scope, epoch or reason is
// therefore writable and then unreplayable. It must be a definite refusal at the
// write path instead.
func TestOversizedControlFieldsAreRefusedAtWriteTime(t *testing.T) {
	w := newControlReserveWAL(t)

	cases := []struct {
		name string
		typ  frameType
		v    any
	}{
		{"scope", frameDelegation, delegationFrame{Scope: strings.Repeat("s", maxScopeBytes+1), Epoch: "e"}},
		{"epoch", frameDelegation, delegationFrame{Scope: "d", Epoch: strings.Repeat("e", maxEpochBytes+1)}},
		{"reason", frameForcedClose, closeFrame{Reason: strings.Repeat("r", maxReasonBytes+1)}},
		{"jobID", frameForcedClose, closeFrame{JobID: strings.Repeat("j", maxJobIDBytes+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := w.DiskBytes()
			if err := w.appendControl(tc.typ, tc.v); err == nil {
				t.Fatalf("an over-long %s produced a frame instead of a refusal", tc.name)
			}
			if got := w.DiskBytes(); got != before {
				t.Fatalf("the refused %s frame still wrote %d bytes", tc.name, got-before)
			}
		})
	}

	// Whatever the caps admit must stay replayable: the decoder's payload bound
	// has to dominate every control payload the write path accepts.
	for _, bound := range []int{maxDelegationPayload, maxAppliedPayload, maxClosePayload} {
		if bound > maxMutationPayload {
			t.Fatalf("a control payload bound of %d exceeds the decoder's %d bound", bound, maxMutationPayload)
		}
	}

	// The whole log must still decode.
	if err := w.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := scanStreamReadOnly(w.dir); err != nil {
		t.Fatalf("the stream no longer replays: %v", err)
	}
}

// TestLifecycleIsNeverWedgedAtTheBound is the constraint the reserve exists for.
// A CLOSE, a FORCED_CLOSE or a delegation RELEASE that cannot be written is a
// wedged mount, so at a fully saturated log every one of them must still
// succeed — and still fit.
func TestLifecycleIsNeverWedgedAtTheBound(t *testing.T) {
	const budget = 256 << 10
	oldTarget := segmentTargetBytes
	segmentTargetBytes = 32 << 10
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	w := newControlReserveWAL(t)
	scopes := []string{"a", "b", "c"}
	for _, scope := range scopes {
		if err := w.appendControlWithin(frameDelegation,
			delegationFrame{Scope: scope, Epoch: "epoch-" + scope}, budget); err != nil {
			t.Fatalf("install grant %q: %v", scope, err)
		}
	}
	fillToBudgetEpsilon(t, w, budget)

	for _, scope := range scopes {
		if err := w.recordDrainedRelease(scope, "epoch-"+scope, w.LastSeq(), w.Digest()); err != nil {
			t.Fatalf("release %q at a saturated log: %v", scope, err)
		}
		if got := w.DiskBytes(); got > budget {
			t.Fatalf("releasing %q left the log at %d bytes, past its %d cap", scope, got, budget)
		}
	}
	if err := w.appendControl(frameForcedClose, closeFrame{
		Through: w.LastSeq(), JobID: "job-0001", Reason: "forced unmount",
	}); err != nil {
		t.Fatalf("FORCED_CLOSE at a saturated log: %v", err)
	}
	if err := w.appendControl(frameClose, closeFrame{Through: w.LastSeq()}); err != nil {
		t.Fatalf("CLOSE at a saturated log: %v", err)
	}
	if got := w.DiskBytes(); got > budget {
		t.Fatalf("lifecycle close-out left the log at %d bytes, past its %d cap", got, budget)
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := scanStreamReadOnly(w.dir); err != nil {
		t.Fatalf("the closed-out stream no longer replays: %v", err)
	}
}

// TestControlReserveDominatesCloseOut states the reserve's arithmetic as an
// executable claim: whatever the live set, the bytes the reserve holds back are
// at least the bytes a full close-out of that set writes.
func TestControlReserveDominatesCloseOut(t *testing.T) {
	oldTarget := segmentTargetBytes
	// A rotation threshold no larger than a bare segment header puts every
	// single control operation past it: the worst case for the rollover term,
	// reached without fabricating a byte.
	segmentTargetBytes = segmentHeaderSize
	t.Cleanup(func() { segmentTargetBytes = oldTarget })

	w := newControlReserveWAL(t)
	const budget = 1 << 30
	const live = 16
	for i := 0; i < live; i++ {
		if err := w.appendControlWithin(frameDelegation, delegationFrame{
			Scope: fmt.Sprintf("scope-%02d", i), Epoch: fmt.Sprintf("epoch-%02d", i),
		}, budget); err != nil {
			t.Fatalf("install grant %d: %v", i, err)
		}
	}
	w.mu.Lock()
	reserve := w.controlReserveLocked(0, 0)
	w.mu.Unlock()

	before := w.DiskBytes()
	for i := 0; i < live; i++ {
		scope := fmt.Sprintf("scope-%02d", i)
		if err := w.recordDrainedRelease(scope, fmt.Sprintf("epoch-%02d", i), 0, digestZero()); err != nil {
			t.Fatalf("release %s: %v", scope, err)
		}
	}
	if err := w.appendControl(frameForcedClose, closeFrame{
		JobID: strings.Repeat("j", maxJobIDBytes), Reason: strings.Repeat("r", maxReasonBytes),
	}); err != nil {
		t.Fatalf("forced close: %v", err)
	}
	if err := w.appendControl(frameClose, closeFrame{}); err != nil {
		t.Fatalf("close: %v", err)
	}
	if spent := w.DiskBytes() - before; spent > reserve {
		t.Fatalf("close-out wrote %d bytes, more than the %d-byte reserve held back for it", spent, reserve)
	}
}
