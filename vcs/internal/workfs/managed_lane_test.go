package workfs

// Round 7, authority side: a mount write-back stream is TWO independently-
// applicable lanes, each with its own dense sequence, its own chained digest and
// its own durable watermark, plus ONE cross-lane dependency that only ever
// points from data to namespace.
//
// These are the durability-side statements. The client-side mechanism lives in
// writeback/lane_separation_test.go; the end-to-end contract they exist to serve
// is portablefsd's TestMetadataStaysInteractiveUnderADataFlood.

import (
	"errors"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// TestLaneWatermarksAdvanceIndependently is the whole point, stated durably: a
// namespace batch advances the namespace watermark WITHOUT touching the data
// watermark, and vice versa. Before round 7 there was one watermark, so this
// question could not even be asked.
func TestLaneWatermarksAdvanceIndependently(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-lanes", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb-lanes")

	ns := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
		{Seq: 2, Record: wal.Record{Op: wal.OpCreate, Path: "ws/a", Mode: 0o644}},
	}, "ws", epoch)
	nsEnd := flushDigests(t, digestZeroStream(), ns)
	through, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-lanes", Lane: pfc2.StreamLaneNamespace,
		PrevDigest: digestZeroStream(), EndDigest: nsEnd, Rows: ns,
	}, "M")
	if err != nil || through != 2 {
		t.Fatalf("namespace flush: through=%d err=%v", through, err)
	}
	view, ok, _ := fs.ManagedWritebackState("wb-lanes")
	if !ok || view.NSThrough != 2 || view.NSDigest != nsEnd {
		t.Fatalf("namespace lane state %+v ok=%v", view, ok)
	}
	if view.DataThrough != 0 || view.Through != 0 {
		t.Fatalf("a namespace flush moved another lane: %+v", view)
	}

	// The data lane starts at its OWN sequence 1, not at 3: the lanes do not
	// share a numbering space, which is precisely what lets one advance while
	// the other is megabytes behind.
	data := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpWrite, Path: "ws/a", Data: []byte("hello")}},
	}, "ws", epoch)
	dataEnd := flushDigests(t, digestZeroStream(), data)
	through, err = fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-lanes", Lane: pfc2.StreamLaneData, NSRequired: 2,
		PrevDigest: digestZeroStream(), EndDigest: dataEnd, Rows: data,
	}, "M")
	if err != nil || through != 1 {
		t.Fatalf("data flush: through=%d err=%v", through, err)
	}
	view, _, _ = fs.ManagedWritebackState("wb-lanes")
	if view.NSThrough != 2 || view.DataThrough != 1 {
		t.Fatalf("lane watermarks after both flushes: %+v", view)
	}
}

// TestDataFlushIsHeldUntilItsNamespaceDependencyIsApplied is the ONE cross-lane
// rule, and it is a HOLD rather than a verdict: nothing stages, no watermark
// moves, and the identical batch applies unchanged once the namespace lane
// catches up. A retryable refusal is the only honest answer — the batch is
// perfectly valid, it is merely early.
func TestDataFlushIsHeldUntilItsNamespaceDependencyIsApplied(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-dep", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb-dep")

	// The namespace lane holds NOTHING yet, so a data batch that needs
	// namespace record 1 (the create of its inode) cannot apply.
	data := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpWrite, Path: "ws/a", Data: []byte("early")}},
	}, "ws", epoch)
	dataEnd := flushDigests(t, digestZeroStream(), data)
	batch := ManagedFlush{
		WritebackID: "wb-dep", Lane: pfc2.StreamLaneData, NSRequired: 1,
		PrevDigest: digestZeroStream(), EndDigest: dataEnd, Rows: data,
	}
	if _, err := fs.ManagedFlushApply(a, batch, "M"); !errors.Is(err, ErrLaneDependencyUnmet) {
		t.Fatalf("early data flush: %v, want ErrLaneDependencyUnmet", err)
	}
	if _, ok, _ := fs.ManagedWritebackState("wb-dep"); ok {
		t.Fatal("a held batch created durable stream state; a hold must apply nothing")
	}

	// Satisfy the dependency and re-offer the IDENTICAL batch. The dependency
	// is the create of the very inode the data record writes, which is exactly
	// the direction the rule exists to enforce.
	ns := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
		{Seq: 2, Record: wal.Record{Op: wal.OpCreate, Path: "ws/a", Mode: 0o644}},
	}, "ws", epoch)
	nsEnd := flushDigests(t, digestZeroStream(), ns)
	if _, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-dep", Lane: pfc2.StreamLaneNamespace,
		PrevDigest: digestZeroStream(), EndDigest: nsEnd, Rows: ns,
	}, "M"); err != nil {
		t.Fatalf("namespace flush: %v", err)
	}
	if through, err := fs.ManagedFlushApply(a, batch, "M"); err != nil || through != 1 {
		t.Fatalf("re-offered data flush: through=%d err=%v", through, err)
	}
}

// TestOnlyTheDataLaneMayDeclareANamespaceDependency pins the asymmetry itself.
// A namespace batch that names a dependency is a client that has the direction
// backwards, and the direction is the entire soundness argument: if namespace
// records could wait on data, the namespace lane would inherit the bulk
// backlog's drain time again.
func TestOnlyTheDataLaneMayDeclareANamespaceDependency(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-dir", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb-dir")
	rows := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
	}, "ws", epoch)
	end := flushDigests(t, digestZeroStream(), rows)
	for _, lane := range []pfc2.StreamLane{pfc2.StreamLaneLegacy, pfc2.StreamLaneNamespace} {
		if _, err := fs.ManagedFlushApply(a, ManagedFlush{
			WritebackID: "wb-dir", Lane: lane, NSRequired: 1,
			PrevDigest: digestZeroStream(), EndDigest: end, Rows: rows,
		}, "M"); err == nil {
			t.Fatalf("%s lane accepted a namespace dependency", lane)
		}
	}
	if _, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-dir", Lane: pfc2.StreamLane(7),
		PrevDigest: digestZeroStream(), EndDigest: end, Rows: rows,
	}, "M"); err == nil {
		t.Fatal("an unknown lane was accepted; lanes are a closed set")
	}
}

// TestLaneGapsAndDigestDivergenceStayTypedCorruption carries the landed
// single-stream integrity contract into each lane: a sequence gap and a forged
// digest are both ErrWritebackCorrupt, per lane, exactly as they were for the
// one stream.
func TestLaneGapsAndDigestDivergenceStayTypedCorruption(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-corrupt", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb-corrupt")
	ns := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
	}, "ws", epoch)
	nsEnd := flushDigests(t, digestZeroStream(), ns)
	if _, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-corrupt", Lane: pfc2.StreamLaneNamespace,
		PrevDigest: digestZeroStream(), EndDigest: nsEnd, Rows: ns,
	}, "M"); err != nil {
		t.Fatalf("seed namespace lane: %v", err)
	}
	gap := flushRowsForScope([]ManagedFlushRow{
		{Seq: 3, Record: wal.Record{Op: wal.OpCreate, Path: "ws/gap", Mode: 0o644}},
	}, "ws", epoch)
	if _, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-corrupt", Lane: pfc2.StreamLaneNamespace,
		PrevDigest: nsEnd, EndDigest: flushDigests(t, nsEnd, gap), Rows: gap,
	}, "M"); !errors.Is(err, ErrWritebackCorrupt) {
		t.Fatalf("gapped namespace flush: %v, want ErrWritebackCorrupt", err)
	}
	forged := flushRowsForScope([]ManagedFlushRow{
		{Seq: 2, Record: wal.Record{Op: wal.OpCreate, Path: "ws/forged", Mode: 0o644}},
	}, "ws", epoch)
	if _, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-corrupt", Lane: pfc2.StreamLaneNamespace,
		PrevDigest: nsEnd, EndDigest: nsEnd, Rows: forged,
	}, "M"); !errors.Is(err, ErrWritebackCorrupt) {
		t.Fatalf("digest-diverging namespace flush: %v, want ErrWritebackCorrupt", err)
	}
	// A batch chained onto the OTHER lane's digest cannot link either: the
	// chains are per lane, so a record cannot be moved between them.
	crossLane := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpWrite, Path: "ws/a", Data: []byte("x")}},
	}, "ws", epoch)
	if _, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-corrupt", Lane: pfc2.StreamLaneData,
		PrevDigest: nsEnd, EndDigest: flushDigests(t, nsEnd, crossLane), Rows: crossLane,
	}, "M"); !errors.Is(err, ErrWritebackCorrupt) {
		t.Fatalf("cross-lane chained flush: %v, want ErrWritebackCorrupt", err)
	}
}

// TestRebindVerifiesEveryLanesPosition: a stream born after the lane boundary
// has a permanently-zero LEGACY watermark, so a rebind that checked only the
// legacy pair would verify nothing at all about it. Every lane is part of the
// claim.
func TestRebindVerifiesEveryLanesPosition(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-rebind-lanes", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb-rebind")
	ns := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
	}, "ws", epoch)
	nsEnd := flushDigests(t, digestZeroStream(), ns)
	if _, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-rebind", Lane: pfc2.StreamLaneNamespace,
		PrevDigest: digestZeroStream(), EndDigest: nsEnd, Rows: ns,
	}, "M"); err != nil {
		t.Fatalf("seed namespace lane: %v", err)
	}
	scopes := []WritebackScope{{Path: "ws", Epoch: epoch}}

	// The legacy pair alone matches (both zero) — and must NOT be enough.
	if conflicts, err := fs.ManagedWritebackConflicts("wb-rebind", scopes, WritebackMark{}); err != nil ||
		len(conflicts) == 0 || conflicts[0].Kind != "DIGEST_MISMATCH" {
		t.Fatalf("a claim that ignores the namespace lane was accepted: conflicts=%+v err=%v", conflicts, err)
	}
	// The full per-lane claim matches.
	full := WritebackMark{NSThrough: 1, NSDigest: nsEnd}
	if conflicts, err := fs.ManagedWritebackConflicts("wb-rebind", scopes, full); err != nil || len(conflicts) != 0 {
		t.Fatalf("exact per-lane claim rejected: conflicts=%+v err=%v", conflicts, err)
	}
	// A wrong lane digest is a mismatch.
	wrong := full
	wrong.NSDigest[0] ^= 0xff
	if conflicts, err := fs.ManagedWritebackConflicts("wb-rebind", scopes, wrong); err != nil ||
		len(conflicts) == 0 || conflicts[0].Kind != "DIGEST_MISMATCH" {
		t.Fatalf("a forged namespace digest was accepted: conflicts=%+v err=%v", conflicts, err)
	}
}

// TestLegacyFlushKeepsItsExactShape is the frozen half: a batch with no lane is
// the legacy single stream, it advances the legacy watermark, and every landed
// legacy assertion keeps holding. Nothing about lanes changes what a
// pre-round-7 client's bytes mean.
func TestLegacyFlushKeepsItsExactShape(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-legacy-lane", 1)
	epoch := grantDelegation(t, fs, a, 0, 1, "ws", "wb-legacy")
	rows := flushRowsForScope([]ManagedFlushRow{
		{Seq: 1, Record: wal.Record{Op: wal.OpMkdir, Path: "ws", Mode: 0o755}},
		{Seq: 2, Record: wal.Record{Op: wal.OpCreate, Path: "ws/a", Mode: 0o644}},
		{Seq: 3, Record: wal.Record{Op: wal.OpWrite, Path: "ws/a", Data: []byte("legacy")}},
	}, "ws", epoch)
	end := flushDigests(t, digestZeroStream(), rows)
	through, err := fs.ManagedFlushApply(a, ManagedFlush{
		WritebackID: "wb-legacy", PrevDigest: digestZeroStream(), EndDigest: end, Rows: rows,
	}, "M")
	if err != nil || through != 3 {
		t.Fatalf("legacy flush: through=%d err=%v", through, err)
	}
	view, ok, _ := fs.ManagedWritebackState("wb-legacy")
	if !ok || view.Through != 3 || view.Digest != end {
		t.Fatalf("legacy stream state %+v ok=%v", view, ok)
	}
	if view.NSThrough != 0 || view.DataThrough != 0 {
		t.Fatalf("an unlaned flush moved a lane watermark: %+v", view)
	}
}
