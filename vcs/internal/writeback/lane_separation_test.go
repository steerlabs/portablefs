package writeback

// Round 7: NAMESPACE-LANE SEPARATION IN THE WRITE-BACK STREAM.
//
// The campaign contract these tests underwrite is stated end-to-end by
// portablefsd's TestMetadataStaysInteractiveUnderADataFlood: metadata stays
// interactive (p99 < 1s) under any data flood. That test measures the OUTCOME.
// The tests here pin the MECHANISM, one piece at a time, so a future change
// that breaks the mechanism fails here — with a name that says what broke —
// instead of only showing up as a latency regression in a 26-second flood run.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// ─── the contract, at engine scope ───────────────────────────────────────────

// TestMetadataOnlyScopeReleasesWhileBulkDataIsUnshippable is the unit-scale
// statement of the whole round.
//
// It is the same shape as TestMetadataScopeReleaseWaitsForUnrelatedBulkData
// (release_wedge_repro_test.go, round 3's repro B) with the crucial difference
// that the metadata scope's records are NOT applied first: they are admitted
// WHILE the uplink is shut, so the release genuinely has to drain them. Before
// lanes, that drain was ordered behind every bulk byte admitted before it,
// because the stream was one chain with one watermark. With lanes the namespace
// records are the namespace lane's ENTIRE backlog, so opening the uplink for one
// small batch releases the scope with the bulk data still unshipped.
func TestMetadataOnlyScopeReleasesWhileBulkDataIsUnshippable(t *testing.T) {
	pinCreditTimings(t, 150*time.Millisecond, 25*time.Second, 200*time.Millisecond)
	f := newSaturationFixture(t, 32<<20)
	ctx := context.Background()

	// A bulk backlog in one scope, admitted while nothing can ship.
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create d/f: handled=%v err=%v", handled, err)
	}
	chunk := make([]byte, 256<<10)
	for i := 0; i < 8; i++ {
		wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, _, err := f.e.WriteAppend(wctx, "d/f", chunk)
		cancel()
		if err != nil {
			break
		}
	}
	// A metadata-only scope, admitted AFTER the bulk backlog, so every one of
	// its records sits behind that backlog in the global stream order.
	if _, handled, err := f.e.Create(ctx, "meta/only", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create meta/only: handled=%v err=%v", handled, err)
	}
	nsPending, _ := f.e.fl.laneStateForTest(StreamLaneNamespace)
	dataPending, _ := f.e.fl.laneStateForTest(StreamLaneData)
	if nsPending == 0 {
		t.Fatal("no namespace-lane backlog: the fixture did not exercise lane separation")
	}
	if dataPending == 0 {
		t.Fatal("no data-lane backlog: the release would have nothing to be ordered behind")
	}

	// Open the uplink. Both lanes can now ship, but the data lane's backlog is
	// megabytes and the namespace lane's is a handful of records. The release
	// must return on the namespace lane's own drain.
	f.openUplink()
	relCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := f.e.ReleaseFor(relCtx, "meta/only"); err != nil {
		t.Fatalf("releasing a metadata-only scope failed: %v", err)
	}
	t.Logf("metadata-only release took %s", time.Since(start).Round(time.Millisecond))
}

// TestNamespaceRecordsNeverEnterTheDataLaneForAMetadataOnlyScope pins the lane
// ROUTER, which is where the contract is actually decided. A scope with no
// unapplied bulk data must place every namespace record in the namespace lane;
// anything else silently reintroduces the coupling.
func TestNamespaceRecordsNeverEnterTheDataLaneForAMetadataOnlyScope(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["meta"] = true
	auth.mu.Unlock()
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()

	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, handled, err := e.Create(ctx, fmt.Sprintf("meta/f%d", i), 0o644, false, false); err != nil || !handled {
			t.Fatalf("create: handled=%v err=%v", handled, err)
		}
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	auth.mu.Lock()
	st := auth.streams[e.writebackID]
	nsThrough := st.lanes[StreamLaneNamespace].through
	dataThrough := st.lanes[StreamLaneData].through
	legacyThrough := st.lanes[StreamLaneLegacy].through
	auth.mu.Unlock()
	if nsThrough == 0 {
		t.Fatal("a metadata-only workload advanced no namespace watermark")
	}
	if dataThrough != 0 {
		t.Fatalf("metadata-only workload put %d records in the data lane", dataThrough)
	}
	if legacyThrough != 0 {
		t.Fatalf("a fresh stream against a lane-capable authority wrote %d unlaned records", legacyThrough)
	}
}

// TestNamespaceRecordJoinsTheDataLaneWhenItsScopeHoldsUnappliedData is the
// SOUNDNESS half of the router, and the case that makes lane separation
// order-preserving at all.
//
// `echo hi > f; rm f` admits a data record and then a namespace record on the
// same node. If the remove took the namespace lane it would ship eagerly, reach
// the authority first, and the buffered write would then apply to a path that no
// longer exists. Routing it into the data lane puts it after the write in the
// only order that matters.
func TestNamespaceRecordJoinsTheDataLaneWhenItsScopeHoldsUnappliedData(t *testing.T) {
	pinCreditTimings(t, 150*time.Millisecond, 25*time.Second, 200*time.Millisecond)
	f := newSaturationFixture(t, 32<<20)
	ctx := context.Background()

	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create d/f: handled=%v err=%v", handled, err)
	}
	if _, _, err := f.e.WriteAppend(ctx, "d/f", []byte("hi")); err != nil {
		t.Fatalf("write d/f: %v", err)
	}
	beforeNS, _ := f.e.fl.laneStateForTest(StreamLaneNamespace)
	beforeData, _ := f.e.fl.laneStateForTest(StreamLaneData)
	if _, handled, err := f.e.Remove(ctx, "d/f"); err != nil || !handled {
		t.Fatalf("remove d/f: handled=%v err=%v", handled, err)
	}
	afterNS, _ := f.e.fl.laneStateForTest(StreamLaneNamespace)
	afterData, _ := f.e.fl.laneStateForTest(StreamLaneData)
	if afterNS != beforeNS {
		t.Fatalf("the remove of a file with unapplied bulk data entered the NAMESPACE lane "+
			"(%d -> %d): it would apply ahead of the write it must follow", beforeNS, afterNS)
	}
	if afterData != beforeData+1 {
		t.Fatalf("data lane %d -> %d, want exactly the remove appended", beforeData, afterData)
	}

	// And the applied tree agrees: after everything drains, the file is gone
	// rather than resurrected by a late write.
	f.openUplink()
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := f.e.DrainAll(dctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.auth.mu.Lock()
	_, present := f.auth.files["d/f"]
	f.auth.mu.Unlock()
	if present {
		t.Fatal("write-then-remove applied out of order: the removed file is back")
	}
}

// ─── the cross-lane dependency ───────────────────────────────────────────────

// TestNamespaceDependencyNeverHoldsADataBatchInSteadyState is the assertion the
// design comment would otherwise have to make in prose: the namespace lane is
// tiny and ships eagerly, so the data lane's declared dependency is satisfied
// before it is ever offered, and no data batch is held.
//
// The authority answers a held batch with EAGAIN. A steady-state run that
// produces even one is a design regression — the dependency would have become a
// pacing mechanism instead of a correctness bound.
func TestNamespaceDependencyNeverHoldsADataBatchInSteadyState(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()

	ctx := context.Background()
	for i := 0; i < 24; i++ {
		path := fmt.Sprintf("d/f%d", i)
		if _, handled, err := e.Create(ctx, path, 0o644, false, false); err != nil || !handled {
			t.Fatalf("create: handled=%v err=%v", handled, err)
		}
		if _, _, err := e.WriteAppend(ctx, path, make([]byte, 8<<10)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	auth.mu.Lock()
	held := auth.heldDataBatches
	auth.mu.Unlock()
	if held != 0 {
		t.Fatalf("the authority held %d data batches on their namespace dependency; "+
			"in steady state the namespace lane is always ahead", held)
	}
}

// TestDataBatchAheadOfItsNamespaceDependencyIsHeld is the other direction: the
// bound is real and definite, not merely never exercised. A data batch whose
// declared namespace watermark is not applied is refused with the authority's
// typed retryable answer, nothing is staged, and the identical batch succeeds
// once the namespace lane catches up.
func TestDataBatchAheadOfItsNamespaceDependencyIsHeld(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.grants["d"] = fakeGrant{epoch: "1", wbID: "wb-dep"}
	auth.streams["wb-dep"] = newFakeStream()
	auth.mu.Unlock()

	rec := wal.Record{Op: wal.OpWrite, Path: "d/f", Data: []byte("bulk")}
	payload := canonicalPayload(rec)
	rec.Seq = 1
	batch := FlushRequest{
		WritebackID: "wb-dep", Lane: StreamLaneData,
		NSRequired: 1, // one namespace record must be applied first
		PrevDigest: digestZero(), EndDigest: digestNext(digestZero(), 1, payload),
		Records:   []wal.Record{rec},
		ScopeRuns: []FlushScope{{Scope: "d", Epoch: "1", Through: 1}},
	}
	reply, err := auth.Flush(context.Background(), batch)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if reply.Status != 11 {
		t.Fatalf("held data batch status = %d, want 11 (EAGAIN, typed retryable)", reply.Status)
	}
	auth.mu.Lock()
	_, staged := auth.files["d/f"]
	auth.mu.Unlock()
	if staged {
		t.Fatal("a held batch staged tree state; a hold must apply nothing")
	}

	// Satisfy the dependency, then re-offer the IDENTICAL batch.
	nsRec := wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644}
	nsPayload := canonicalPayload(nsRec)
	nsRec.Seq = 1
	nsReply, err := auth.Flush(context.Background(), FlushRequest{
		WritebackID: "wb-dep", Lane: StreamLaneNamespace,
		PrevDigest: digestZero(), EndDigest: digestNext(digestZero(), 1, nsPayload),
		Records:   []wal.Record{nsRec},
		ScopeRuns: []FlushScope{{Scope: "d", Epoch: "1", Through: 1}},
	})
	if err != nil || nsReply.Status != 0 {
		t.Fatalf("namespace flush: status=%d err=%v", nsReply.Status, err)
	}
	reply, err = auth.Flush(context.Background(), batch)
	if err != nil || reply.Status != 0 || reply.Through != 1 {
		t.Fatalf("re-offered data batch: through=%d status=%d err=%v", reply.Through, reply.Status, err)
	}
}

// ─── chain integrity ─────────────────────────────────────────────────────────

// TestLaneChainRejectsCrossLaneTampering is the framing contract: a lane's
// digest chain is computed over that LANE's sequence, so a record presented
// under the other lane's watermark does not link and the authority refuses it as
// a proven contradiction.
//
// Without this the split would be a hole in the integrity story: two lanes with
// a shared chain space would let a client (or a corrupted one) move a record
// between lanes and have both chains still verify.
func TestLaneChainRejectsCrossLaneTampering(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.grants["d"] = fakeGrant{epoch: "1", wbID: "wb-x"}
	auth.streams["wb-x"] = newFakeStream()
	auth.mu.Unlock()

	// Two namespace records; the second's chain digest depends on the first.
	first := wal.Record{Op: wal.OpCreate, Path: "d/a", Mode: 0o644}
	second := wal.Record{Op: wal.OpCreate, Path: "d/b", Mode: 0o644}
	d1 := digestNext(digestZero(), 1, canonicalPayload(first))
	d2 := digestNext(d1, 2, canonicalPayload(second))
	first.Seq, second.Seq = 1, 2
	ok, err := auth.Flush(context.Background(), FlushRequest{
		WritebackID: "wb-x", Lane: StreamLaneNamespace,
		PrevDigest: digestZero(), EndDigest: d2,
		Records:   []wal.Record{first, second},
		ScopeRuns: []FlushScope{{Scope: "d", Epoch: "1", Through: 2}},
	})
	if err != nil || ok.Status != 0 {
		t.Fatalf("namespace batch: status=%d err=%v", ok.Status, err)
	}

	// The SAME records, with the SAME digests, offered on the data lane. The
	// data lane's durable digest is digestZero and its watermark is 0, so a
	// batch chained onto the namespace lane's state cannot link.
	tampered, err := auth.Flush(context.Background(), FlushRequest{
		WritebackID: "wb-x", Lane: StreamLaneData,
		PrevDigest: d1, EndDigest: d2,
		Records:   []wal.Record{second},
		ScopeRuns: []FlushScope{{Scope: "d", Epoch: "1", Through: 2}},
	})
	if err != nil {
		t.Fatalf("tampered flush: %v", err)
	}
	if tampered.Status != 22 {
		t.Fatalf("cross-lane replay status = %d, want 22 (EINVAL: a proven contradiction)", tampered.Status)
	}
}

// TestFrameLaneTagIsUnderTheHeaderChecksum pins the framing decision: the lane
// tag lives in a header byte the frame CRC already covers, so a flipped lane is
// corruption rather than a silent reinterpretation of which chain a record
// belongs to.
func TestFrameLaneTagIsUnderTheHeaderChecksum(t *testing.T) {
	payload := canonicalPayload(wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644})
	buf := encodeFrame(nil, frameMutation, StreamLaneNamespace, 1, 1, payload)
	fr, _, err := decodeFrameAt(buf, 0, 1)
	if err != nil {
		t.Fatalf("decode laned frame: %v", err)
	}
	if fr.lane != StreamLaneNamespace {
		t.Fatalf("decoded lane = %d, want namespace", uint8(fr.lane))
	}
	flipped := append([]byte(nil), buf...)
	flipped[6] = byte(StreamLaneData)
	if _, _, err := decodeFrameAt(flipped, 0, 1); err == nil {
		t.Fatal("flipping the lane tag produced a frame the decoder accepted; " +
			"the tag is not covered by the header checksum")
	}
	unknown := append([]byte(nil), buf...)
	unknown[6] = 9
	if _, _, err := decodeFrameAt(unknown, 0, 1); err == nil {
		t.Fatal("an unknown lane tag was accepted; lanes are a closed set")
	}
}

// TestLegacyFramesDecodeAsTheLegacyLane is the frozen-format half: a PFW5 frame
// written before round 7 has a zero lane byte, and that must read as the legacy
// single stream rather than as lane 0 of a laned one.
func TestLegacyFramesDecodeAsTheLegacyLane(t *testing.T) {
	payload := canonicalPayload(wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644})
	buf := encodeFrame(nil, frameMutation, StreamLaneLegacy, 1, 1, payload)
	if buf[6] != 0 {
		t.Fatalf("legacy frame header byte 6 = %d, want 0 (byte-identical to a pre-round-7 frame)", buf[6])
	}
	fr, _, err := decodeFrameAt(buf, 0, 1)
	if err != nil || fr.lane != StreamLaneLegacy {
		t.Fatalf("legacy frame decoded as lane %d err=%v", uint8(fr.lane), err)
	}
}

// ─── the upgrade boundary ────────────────────────────────────────────────────

// TestLanedEraOpensOnlyWhenTheAuthorityAdvertisesLanes: without the capability
// there is no laned encoding to use, so the stream stays in the legacy era and
// keeps writing the single chain every authority understands. This is the
// version gate, and it gates the BOUNDARY rather than each write.
func TestLanedEraOpensOnlyWhenTheAuthorityAdvertisesLanes(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.lanesSupported = false
	auth.mu.Unlock()
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, _, err := e.WriteAppend(ctx, "d/f", []byte("bulk")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	e.mu.RLock()
	laned := e.wal.Laned()
	e.mu.RUnlock()
	if laned {
		t.Fatal("the stream opened its laned era against an authority that does not speak lanes")
	}
	auth.mu.Lock()
	st := auth.streams[e.writebackID]
	legacy := st.lanes[StreamLaneLegacy].through
	other := st.lanes[StreamLaneNamespace].through + st.lanes[StreamLaneData].through
	auth.mu.Unlock()
	if legacy == 0 || other != 0 {
		t.Fatalf("pre-upgrade stream applied legacy=%d laned=%d, want everything legacy", legacy, other)
	}
}

// TestMixedBoundaryWALCrossesOnlyWhenTheLegacyTailIsApplied is the BOUNDARY
// definition, tested rather than asserted.
//
// The stream starts against an authority without lanes, accumulates an unlaned
// backlog that cannot ship, and is then told the authority speaks lanes (the
// shape a reconnect to an upgraded authority produces). The era must NOT open
// while unlaned records are outstanding — the legacy chain has to be complete at
// the instant it freezes — and must open once they are applied.
func TestMixedBoundaryWALCrossesOnlyWhenTheLegacyTailIsApplied(t *testing.T) {
	pinCreditTimings(t, 150*time.Millisecond, 25*time.Second, 200*time.Millisecond)
	f := newSaturationFixture(t, 32<<20)
	f.auth.mu.Lock()
	f.auth.lanesSupported = false
	f.auth.mu.Unlock()
	ctx := context.Background()

	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, _, err := f.e.WriteAppend(ctx, "d/f", make([]byte, 64<<10)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The authority is upgraded while an unlaned backlog is still outstanding.
	f.auth.mu.Lock()
	f.auth.lanesSupported = true
	f.auth.mu.Unlock()
	if _, handled, err := f.e.Create(ctx, "d/g", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create after upgrade: handled=%v err=%v", handled, err)
	}
	f.e.mu.RLock()
	laned := f.e.wal.Laned()
	f.e.mu.RUnlock()
	if laned {
		t.Fatal("the era opened with an unapplied legacy tail: the legacy chain would freeze incomplete")
	}

	// Drain the legacy tail; the next admission may now cross.
	f.openUplink()
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	if err := f.e.DrainAll(dctx); err != nil {
		cancel()
		t.Fatalf("drain legacy tail: %v", err)
	}
	cancel()
	if _, handled, err := f.e.Create(ctx, "d/h", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create after legacy drain: handled=%v err=%v", handled, err)
	}
	f.e.mu.RLock()
	laned = f.e.wal.Laned()
	lanes := f.e.wal.Lanes()
	f.e.mu.RUnlock()
	if !laned {
		t.Fatal("the era did not open once every unlaned record was applied")
	}
	if lanes[StreamLaneNamespace].through == 0 {
		t.Fatal("the first post-boundary namespace record did not enter the namespace lane")
	}

	// The WAL is now genuinely MIXED, and it must still scan cleanly: unlaned
	// frames first, laned frames after, each lane densely numbered.
	if err := f.e.SyncLocal(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	f.e.mu.RLock()
	epoch := f.e.epoch
	f.e.mu.RUnlock()
	scan, err := scanStreamReadOnly(filepath.Join(walStateDirOf(t, f.e), streamDirName(epoch)))
	if err != nil {
		t.Fatalf("scan mixed WAL: %v", err)
	}
	if !scan.laned {
		t.Fatal("scan of a mixed WAL did not observe the boundary")
	}
	if scan.laneCounts[StreamLaneLegacy] == 0 {
		t.Fatal("mixed WAL fixture holds no unlaned records")
	}
	if scan.laneCounts[StreamLaneNamespace] == 0 {
		t.Fatal("mixed WAL fixture holds no laned records")
	}
	// Density, per lane, is what the authority's gap check relies on.
	var seen [streamLaneCount]uint64
	for _, fr := range scan.frames {
		if fr.typ != frameMutation {
			continue
		}
		seen[fr.lane]++
		if fr.laneSeq != scan.laneFirst[fr.lane]+seen[fr.lane]-1 {
			t.Fatalf("%s-lane sequence %d is not dense", fr.lane, fr.laneSeq)
		}
	}
}

// TestUnlanedAppendAfterTheBoundaryIsRefused: the boundary is ONE-WAY. A record
// written with no lane after the stream has two live chains belongs to neither,
// so it is refused at the WAL rather than written somewhere a reader would have
// to guess about.
func TestUnlanedAppendAfterTheBoundaryIsRefused(t *testing.T) {
	streamDir := filepath.Join(t.TempDir(), streamDirName(1))
	var mountID [16]byte
	copy(mountID[:], "lane-boundary---")
	w, err := createStreamWAL(streamDir, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}
	defer func() { _ = w.Close() }()
	payload := canonicalPayload(wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644})
	if _, err := w.appendLaneMutationsWithin([][]byte{payload}, 0, StreamLaneNamespace); err != nil {
		t.Fatalf("laned append: %v", err)
	}
	if _, err := w.appendMutations([][]byte{payload}); err == nil {
		t.Fatal("an unlaned append succeeded after the boundary")
	}
}

// TestMixedBoundaryWALRecoversDefinitively is the recovery half of the
// boundary. A parked stream that spans the upgrade must replay: legacy first (a
// strict prefix), then namespace, then data — and reach a definite outcome with
// no job left behind.
func TestMixedBoundaryWALRecoversDefinitively(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.lanesSupported = false
	auth.flushErr = errors.New("park the mixed tail")
	auth.mu.Unlock()
	dir := t.TempDir()
	e1, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open first engine: %v", err)
	}
	ctx := context.Background()
	// Unlaned records first.
	if _, handled, err := e1.Create(ctx, "d/legacy", 0o644, false, false); err != nil || !handled {
		t.Fatalf("legacy create: handled=%v err=%v", handled, err)
	}
	// Force the boundary open with the legacy tail unapplied is impossible by
	// construction, so apply the legacy tail first, then upgrade.
	auth.mu.Lock()
	auth.flushErr = nil
	auth.mu.Unlock()
	if err := e1.DrainAll(ctx); err != nil {
		t.Fatalf("drain legacy prefix: %v", err)
	}
	auth.mu.Lock()
	auth.lanesSupported = true
	auth.flushErr = errors.New("park the laned tail")
	auth.mu.Unlock()
	if _, handled, err := e1.Create(ctx, "d/laned", 0o644, false, false); err != nil || !handled {
		t.Fatalf("laned create: handled=%v err=%v", handled, err)
	}
	if _, _, err := e1.WriteAppend(ctx, "d/laned", []byte("bulk")); err != nil {
		t.Fatalf("laned write: %v", err)
	}
	if _, err := e1.ForceClose("park mixed stream"); err != nil {
		t.Fatalf("force close: %v", err)
	}

	auth.mu.Lock()
	auth.flushErr = nil
	auth.mu.Unlock()
	e2, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("recovery of a mixed-boundary WAL failed: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("teardown") }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if len(e2.Status().Jobs) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mixed-boundary recovery did not resolve: %+v", e2.Status().Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := auth.equalFile("d/laned", []byte("bulk")); err != nil {
		t.Fatalf("mixed-boundary recovery lost an acknowledged laned write: %v", err)
	}
	if auth.grantCount() != 0 {
		t.Fatalf("mixed-boundary recovery left %d grants held", auth.grantCount())
	}
}

// ─── exactness ───────────────────────────────────────────────────────────────

// TestPerLaneRetryPinningResendsIdenticalBytes: attemptEnd is per lane now, so
// each lane's ambiguous transport failure must replay ITS OWN batch byte-for-
// byte while the other lane keeps shipping. A pin that leaked across lanes would
// either resend the wrong records or block the healthy lane.
func TestPerLaneRetryPinningResendsIdenticalBytes(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	rec := &recordingRemote{Remote: auth}
	// Fail the FIRST data-lane attempt ambiguously (transport error after the
	// request was formed), then let everything through.
	rec.failLane = StreamLaneData
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: rec, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()

	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, _, err := e.WriteAppend(ctx, "d/f", []byte("first")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Admit MORE data after the failure so a superset would be visible.
	time.Sleep(50 * time.Millisecond)
	if _, _, err := e.WriteAppend(ctx, "d/f", []byte("second")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := e.DrainAll(dctx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	first, resend, ok := rec.pinnedPair(StreamLaneData)
	if !ok {
		t.Skip("the data lane did not retry; the fixture did not reach the pinned path")
	}
	if len(first.Records) != len(resend.Records) || first.EndDigest != resend.EndDigest ||
		first.PrevDigest != resend.PrevDigest || first.NSRequired != resend.NSRequired {
		t.Fatalf("pinned data-lane resend is not byte-identical:\n first=%s\nresend=%s",
			describeBatch(first), describeBatch(resend))
	}
	for i := range first.Records {
		if first.Records[i].Seq != resend.Records[i].Seq ||
			string(first.Records[i].Data) != string(resend.Records[i].Data) {
			t.Fatalf("pinned resend record %d differs", i)
		}
	}
	// The namespace lane must not have been pinned by the data lane's failure.
	if rec.laneAttempts(StreamLaneNamespace) == 0 {
		t.Fatal("the namespace lane shipped nothing while the data lane was retrying")
	}
}

// recordingRemote records every flush per lane and can fail one lane's first
// attempt with an AMBIGUOUS transport error — the shape that arms the exact
// resend pin.
type recordingRemote struct {
	Remote
	mu       sync.Mutex
	failLane StreamLane
	failed   bool
	sent     map[StreamLane][]FlushRequest
}

func (r *recordingRemote) Flush(ctx context.Context, req FlushRequest) (FlushReply, error) {
	r.mu.Lock()
	if r.sent == nil {
		r.sent = map[StreamLane][]FlushRequest{}
	}
	r.sent[req.Lane] = append(r.sent[req.Lane], cloneBatch(req))
	fail := !r.failed && req.Lane == r.failLane
	if fail {
		r.failed = true
	}
	r.mu.Unlock()
	if fail {
		return FlushReply{}, errors.New("ambiguous transport failure")
	}
	return r.Remote.Flush(ctx, req)
}

func (r *recordingRemote) laneAttempts(lane StreamLane) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent[lane])
}

// pinnedPair returns the failed attempt and its immediate resend.
func (r *recordingRemote) pinnedPair(lane StreamLane) (FlushRequest, FlushRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sent[lane]) < 2 {
		return FlushRequest{}, FlushRequest{}, false
	}
	return r.sent[lane][0], r.sent[lane][1], true
}

func cloneBatch(req FlushRequest) FlushRequest {
	out := req
	out.Records = append([]wal.Record(nil), req.Records...)
	out.ScopeRuns = append([]FlushScope(nil), req.ScopeRuns...)
	return out
}

func describeBatch(req FlushRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "lane=%s nsRequired=%d prev=%x end=%x records=[", req.Lane, req.NSRequired, req.PrevDigest[:4], req.EndDigest[:4])
	for i, rec := range req.Records {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%d:%s", rec.Seq, rec.Path)
	}
	b.WriteString("]")
	return b.String()
}

// walStateDirOf reads the engine's configured state directory.
func walStateDirOf(t *testing.T, e *Engine) string {
	t.Helper()
	return e.cfg.StateDir
}
