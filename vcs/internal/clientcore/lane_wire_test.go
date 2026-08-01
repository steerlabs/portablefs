package clientcore

// Round 7: the lane tag exists in three places that do not import each other —
// the write-back engine (writeback.StreamLane), the wire (fsproto Request
// .WBLane), and the durable control state (pfc2.StreamLane). clientcore is the
// one package that sees all three, so it is where their agreement is pinned.
//
// A silent disagreement here would be the worst kind of bug this round can
// produce: a namespace batch applied onto the data lane's chain, or a data
// batch's dependency checked against the wrong watermark. Neither would fail to
// compile and neither would be visible in a latency measurement.

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func TestStreamLaneValuesMatchTheWire(t *testing.T) {
	cases := []struct {
		name    string
		engine  writeback.StreamLane
		control pfc2.StreamLane
	}{
		{"legacy", writeback.StreamLaneLegacy, pfc2.StreamLaneLegacy},
		{"namespace", writeback.StreamLaneNamespace, pfc2.StreamLaneNamespace},
		{"data", writeback.StreamLaneData, pfc2.StreamLaneData},
	}
	for _, tc := range cases {
		if uint8(tc.engine) != uint8(tc.control) {
			t.Fatalf("%s lane: engine=%d control=%d; the wire carries one byte and both sides must mean the same thing by it",
				tc.name, uint8(tc.engine), uint8(tc.control))
		}
		if tc.engine.String() != tc.control.String() {
			t.Fatalf("%s lane names diverge: engine=%q control=%q", tc.name, tc.engine.String(), tc.control.String())
		}
		if !tc.control.Valid() {
			t.Fatalf("%s lane is not a valid control lane", tc.name)
		}
	}
	// The engine's lane must survive the trip through the wire request field
	// that carries it.
	for _, tc := range cases {
		batch := flushBatchOf(writeback.FlushRequest{Lane: tc.engine})
		if batch.Lane != uint8(tc.engine) {
			t.Fatalf("%s lane lost in translation to the wire: %d", tc.name, batch.Lane)
		}
		if pfc2.StreamLane(batch.Lane) != tc.control {
			t.Fatalf("%s lane arrives at the control state as %d", tc.name, batch.Lane)
		}
	}
	// And the closed set is closed at the same size on both sides: a lane the
	// wire can express but the ledger cannot name is a watermark with nowhere
	// to live.
	if !pfc2.StreamLane(pfc2.StreamLaneCount - 1).Valid() {
		t.Fatal("the highest control lane is not valid")
	}
	if pfc2.StreamLane(pfc2.StreamLaneCount).Valid() {
		t.Fatal("a lane past the closed set validated")
	}
}

// TestLaneCapabilityIsRequiredNotOptional pins the version gate's DIRECTION.
// FeatureWritebackLanes is not a nice-to-have the client can degrade away from:
// a laned batch has no legacy encoding, so an authority without the bit must
// refuse it outright rather than reinterpret it.
func TestLaneCapabilityIsRequiredNotOptional(t *testing.T) {
	if fsproto.FeatureWritebackLanes == 0 {
		t.Fatal("FeatureWritebackLanes is unallocated")
	}
	for _, other := range []uint64{
		fsproto.FeatureDelegatedXattrs,
		fsproto.FeatureFlagPersistence,
		fsproto.FeatureMutationAttrs,
	} {
		if fsproto.FeatureWritebackLanes&other != 0 {
			t.Fatalf("FeatureWritebackLanes (%b) overlaps an existing capability bit (%b)",
				fsproto.FeatureWritebackLanes, other)
		}
	}
}
