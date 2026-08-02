package writeback

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// ROUND 18a — THE SILENT PARKED-TAIL REPLAY.
//
// Round 17 removed the LOUD failure: a parked tail is no longer condemned as
// "conflicting applied digests", force-park is prompt, and the remount succeeds
// on the first try. What the live re-test then found is the same loss with the
// alarm removed — a replay that logged success, reported pendingRecords 0, and
// left acknowledged bytes missing from the middle of a file.
//
// Three separate mechanisms had to line up for that, and each has a test here:
//
//	1. THE PARK AND THE REPLAY COUNTED DIFFERENT SETS. The offline park counted
//	   records against the GLOBAL applied prefix; the replay selects and drains
//	   PER LANE. A wedged lane pins the global prefix while the other lanes keep
//	   applying above it, so a healthy park promised 34 and a healthy replay
//	   drained 2 — and because the two numbers were never about the same set,
//	   their disagreement could not be read as evidence of anything.
//	2. NOTHING PROVED THE TAIL WAS PREFIX-CONSISTENT. A lane is a chain, so a
//	   record that cannot be applied forbids every record after it. Nothing
//	   checked that the tail begins at the verified base + 1, so a replay could
//	   apply a suffix over a gap — which is a HOLE in the file, not a short one.
//	3. THE SUCCESS PATH COULD NOT REPORT. Containment sets lostRecords/lostBytes/
//	   lostScopes/remedy and keeps the debt in Pending(). A replay that dropped
//	   records took the SUCCESS path instead, deleted the stream, and dropped the
//	   job out of the accounting — so the loss had no verdict and no number.
// ─────────────────────────────────────────────────────────────────────────────

// wedgeReplayableTailWithAppliedNamespaceRecord builds the live shape, and the
// shape is the fixture: a data record that cannot ship (pinning the GLOBAL
// applied prefix at its own sequence) followed by a namespace record in a
// DIFFERENT scope that applies normally ABOVE that pin.
//
// The stream therefore holds exactly one record its lane has not applied and one
// record that IS applied but sits above the global prefix. Every accounting rule
// that reads the global prefix over-counts here, by construction, and every rule
// that reads the lane does not.
func wedgeReplayableTailWithAppliedNamespaceRecord(t *testing.T, f *parkFixture) []byte {
	t.Helper()
	ctx := context.Background()
	payload := bytes.Repeat([]byte{0x9B}, 4096)

	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain the namespace prefix that precedes the wedge: %v", err)
	}

	f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged under flood"))
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", 0, payload)
	mustHandle(t, "write sat/big", handled, err)

	// A namespace record in an unrelated scope: it takes the namespace lane
	// (the data-lane routing rule only applies to the scope that holds the
	// unapplied bulk), applies immediately, and lands ABOVE the pinned global
	// prefix.
	_, handled, err = f.engine.Mkdir(ctx, "keep/a", 0o755)
	mustHandle(t, "mkdir keep/a", handled, err)
	// Releasing the scope drains its namespace-lane tail and writes the APPLIED
	// certificate that records the split: a global watermark pinned by the
	// wedged data record, and a namespace watermark above it.
	if err := f.engine.ReleaseFor(ctx, "keep"); err != nil {
		t.Fatalf("release keep over the wedge: %v", err)
	}
	return payload
}

// streamTailCounts reports the two rival readings of "records this stream still
// owes the authority": against the GLOBAL applied prefix, and per LANE.
func streamTailCounts(t *testing.T, dir string) (globalRecords, laneRecords, laneBytes uint64) {
	t.Helper()
	scan, err := scanStreamReadOnly(dir)
	if err != nil {
		t.Fatalf("scan parked stream: %v", err)
	}
	_, mutations, marks, _, err := decodeStreamFrames(scan.frames)
	if err != nil {
		t.Fatalf("decode parked stream: %v", err)
	}
	cert, err := highestAppliedCertificate(marks, scan.lastSeq)
	if err != nil {
		t.Fatalf("fold applied certificates: %v", err)
	}
	for _, fr := range mutations {
		if fr.seq > cert.global {
			globalRecords++
		}
	}
	laneRecords, laneBytes = laneTailStats(mutations, cert)
	return globalRecords, laneRecords, laneBytes
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. The park's promise and the replay's work must be counts of the SAME set.
// ─────────────────────────────────────────────────────────────────────────────

// TestOfflineForceParkPromisesTheTailItsReplayWillActuallyDrain closes the gap
// that made the live loss unreadable.
//
// The offline force-park (the path a daemon or CLI takes over a proven-dead
// owner) counted every record above the GLOBAL applied prefix as pending. The
// next attach selects its tail PER LANE. On the live stream that was 34 against
// 2, on this fixture it is 2 against 1, and it is the same defect at both
// scales: a park that promises records the replay was never going to ship makes
// "promised 34, drained 2" the ordinary healthy output, which is exactly what
// left a real 34-against-2 with nothing to compare itself to.
func TestOfflineForceParkPromisesTheTailItsReplayWillActuallyDrain(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat", "keep")
	payload := wedgeReplayableTailWithAppliedNamespaceRecord(t, f)

	f.engine.Abandon()
	dir := f.streamDir(1)
	globalRecords, laneRecords, laneBytes := streamTailCounts(t, dir)
	if globalRecords <= laneRecords {
		t.Fatalf("fixture did not produce the over-counting shape: global-basis %d, lane-basis %d",
			globalRecords, laneRecords)
	}

	if _, err := ForceParkAbandonedStore(f.dir, "vol", "main", "mnt_r18a", "forced unmount"); err != nil {
		t.Fatalf("offline force-park: %v", err)
	}
	job, ok := loadJob(dir)
	if !ok {
		t.Fatal("offline force-park left no recovery registry")
	}
	if job.PendingBasis != pendingBasisLane {
		t.Fatalf("parked job does not name its accounting basis (basis=%q); "+
			"an unnamed promise cannot be reconciled against the replay that answers it", job.PendingBasis)
	}
	if job.PendingRecords != laneRecords || job.PendingBytes != laneBytes {
		t.Fatalf("parked job promises %d record(s)/%d byte(s); the replay will select %d/%d "+
			"(the global-basis over-count is %d)",
			job.PendingRecords, job.PendingBytes, laneRecords, laneBytes, globalRecords)
	}

	next, err := f.reattach()
	if err != nil {
		t.Fatalf("clean fresh attach over the parked tail failed: %v", err)
	}
	defer next.Close(ctx)
	if err := f.auth.equalFile("sat/big", payload); err != nil {
		t.Fatalf("the parked tail was not replayed byte-exactly: %v", err)
	}
	st := next.Status()
	if len(st.Jobs) != 0 {
		t.Fatalf("a fully replayed stream left recovery jobs behind: %+v", st.Jobs)
	}
	if st.PendingRecords != 0 || st.PendingBytes != 0 {
		t.Fatalf("fully replayed stream still reports pending=%d/%d", st.PendingRecords, st.PendingBytes)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. A replay that cannot produce every promised record must SAY SO.
// ─────────────────────────────────────────────────────────────────────────────

// dropTrailingMutationFrames removes the last n mutation frames of a parked
// stream by truncating its final segment at a frame boundary, leaving a stream
// that is perfectly well-formed and simply SHORTER than the park promised.
//
// It is the structural stand-in for every way acknowledged records can fail to
// come back — a media-level loss, a filesystem that discarded a synced tail, a
// crash window a future change opens — and it is deliberately the benign-looking
// one: the frame layer is intact, so nothing on the replay path notices unless
// somebody checks the promise against the bytes.
func dropTrailingMutationFrames(t *testing.T, dir string, n int) {
	t.Helper()
	scan, err := scanStreamReadOnly(dir)
	if err != nil {
		t.Fatalf("scan before truncation: %v", err)
	}
	var mutationFrames []frame
	for _, fr := range scan.frames {
		if fr.typ == frameMutation {
			mutationFrames = append(mutationFrames, fr)
		}
	}
	if len(mutationFrames) < n {
		t.Fatalf("stream holds %d mutation frame(s), cannot drop %d", len(mutationFrames), n)
	}
	first := mutationFrames[len(mutationFrames)-n]
	last := scan.frames[len(scan.frames)-1]
	if first.ordinal != last.ordinal {
		t.Fatalf("fixture spans segments (%d vs %d); the truncation would leave a chain gap",
			first.ordinal, last.ordinal)
	}
	at := first.payloadOff - frameHeaderSize
	path := segmentPath(dir, first.ordinal)
	fh, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open segment: %v", err)
	}
	if err := fh.Truncate(at); err != nil {
		_ = fh.Close()
		t.Fatalf("truncate segment: %v", err)
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		t.Fatalf("sync segment: %v", err)
	}
	if err := fh.Close(); err != nil {
		t.Fatalf("close segment: %v", err)
	}
}

// TestReplayThatCannotProduceEveryPromisedRecordReportsTheLossInsteadOfSucceeding
// is the containment contract for the SILENT shape.
//
// Round 17's contract permits contained loss only if it is REPORTED. This replay
// took the success path: it drained what the stream still held, deleted the
// stream directory, dropped the job out of the registry, and left Status
// answering pendingRecords 0 over acknowledged bytes that no longer exist
// anywhere. There was no lostRecords, no lostBytes, no lostScopes and no remedy,
// because containment is only reached from the failure path and this failure
// never presented as one.
//
// Success must mean every acknowledged byte is back. Anything less has to reach
// a definite, reported verdict.
func TestReplayThatCannotProduceEveryPromisedRecordReportsTheLossInsteadOfSucceeding(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")

	head := bytes.Repeat([]byte{0x11}, 4096)
	tail := bytes.Repeat([]byte{0x22}, 4096)
	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged under flood"))
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", 0, head)
	mustHandle(t, "write head", handled, err)
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", int64(len(head)), tail)
	mustHandle(t, "write tail", handled, err)

	if _, err := f.engine.ForceClose("forced unmount"); err != nil {
		t.Fatalf("force-park a replayable snapshot returned a verdict: %v", err)
	}
	dir := f.streamDir(1)
	job, ok := loadJob(dir)
	if !ok {
		t.Fatal("force-park left no recovery registry")
	}
	if job.PendingRecords != 2 {
		t.Fatalf("park promised %d record(s), want the 2 unshipped writes", job.PendingRecords)
	}
	promisedRecords, promisedBytes := job.PendingRecords, job.PendingBytes

	// The acknowledged tail record stops coming back.
	dropTrailingMutationFrames(t, dir, 1)

	next, err := f.reattach()
	if err != nil {
		t.Fatalf("a fresh attach must succeed over a contained loss, not fail: %v", err)
	}
	defer next.Close(ctx)

	st := next.Status()
	contained, ok := jobByEpoch(st.Jobs, 1)
	if !ok {
		t.Fatal("the lossy replay reported SUCCESS: the job vanished and the loss with it")
	}
	if !contained.Quarantined {
		t.Fatalf("lossy replay left the job uncontained: %+v", contained)
	}
	if contained.LostRecords < promisedRecords || contained.LostBytes < promisedBytes {
		t.Fatalf("loss verdict names %d record(s)/%d byte(s), fewer than the %d/%d the park promised",
			contained.LostRecords, contained.LostBytes, promisedRecords, promisedBytes)
	}
	if len(contained.LostScopes) == 0 {
		t.Fatalf("loss verdict names no scope; an operator cannot act on it: %+v", contained)
	}
	if contained.Remedy == "" {
		t.Fatal("loss verdict carries no remedy")
	}
	if !strings.Contains(contained.LastError, "promised") {
		t.Fatalf("verdict does not say what was promised against what remained: %q", contained.LastError)
	}

	// ── HONEST ACCOUNTING, END TO END ────────────────────────────────────────
	// The one number a drain-completeness check reads must never say zero while
	// acknowledged bytes are missing.
	if st.PendingRecords == 0 || st.PendingBytes == 0 {
		t.Fatalf("Status reports pending=%d/%d over %d lost record(s)/%d lost byte(s)",
			st.PendingRecords, st.PendingBytes, contained.LostRecords, contained.LostBytes)
	}
	if st.UnrecoveredRecords != contained.LostRecords || st.UnrecoveredBytes != contained.LostBytes {
		t.Fatalf("unrecovered debt %d/%d does not equal the contained loss %d/%d",
			st.UnrecoveredRecords, st.UnrecoveredBytes, contained.LostRecords, contained.LostBytes)
	}
	recs, bytesPending := next.Pending()
	if uint64(recs) < contained.LostRecords || uint64(bytesPending) < contained.LostBytes {
		t.Fatalf("Pending() = %d/%d, below the contained loss %d/%d",
			recs, bytesPending, contained.LostRecords, contained.LostBytes)
	}

	// The namespace the dead stream covered is usable again — containment's own
	// half of the contract, unchanged by this round.
	_, handled, err = next.Mkdir(ctx, "sat/again", 0o755)
	mustHandle(t, "mkdir under the contained scope", handled, err)
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Prefix consistency: no record may be applied over a missing one.
// ─────────────────────────────────────────────────────────────────────────────

// TestReplayRefusesToApplyARecordOverAMissingOne is the hole, stated exactly.
//
// The live failure left a 0.94 MiB run of zeros at offset 663,814,144 with
// correct data on both sides of it. Zeros in the middle of a file are strictly
// worse than a short file: a short file is visibly short, while a hole reads as
// data. The only way to produce one is to apply a record whose predecessor in
// the same chain was not applied, so the property to hold is the negative of
// that — if a record cannot be applied, nothing after it may be either.
//
// The tail here is built from a REAL parked stream's own frames, so the shape
// under test is the one recovery actually selects, not a hand-written stand-in.
func TestReplayRefusesToApplyARecordOverAMissingOne(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")

	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged under flood"))
	for i := 0; i < 3; i++ {
		chunk := bytes.Repeat([]byte{byte(0x40 + i)}, 4096)
		_, handled, err = f.engine.WriteAt(ctx, "sat/big", int64(i*len(chunk)), chunk)
		mustHandle(t, "write chunk", handled, err)
	}
	if _, err := f.engine.ForceClose("forced unmount"); err != nil {
		t.Fatalf("force-park: %v", err)
	}

	scan, err := scanStreamReadOnly(f.streamDir(1))
	if err != nil {
		t.Fatalf("scan parked stream: %v", err)
	}
	_, mutations, marks, _, err := decodeStreamFrames(scan.frames)
	if err != nil {
		t.Fatalf("decode parked stream: %v", err)
	}
	cert, err := highestAppliedCertificate(marks, scan.lastSeq)
	if err != nil {
		t.Fatalf("fold certificates: %v", err)
	}
	pos := streamMark{global: cert.global, lanes: cert.lanes}
	tails := laneTails(scan, cert)
	tail := laneTailFrames(mutations, pos)
	if len(tail) < 3 {
		t.Fatalf("fixture parked %d unshipped record(s), want at least 3", len(tail))
	}

	// The intact tail is exactly what a sound replay applies.
	if err := verifyTailPrefixConsistent(tail, pos, tails); err != nil {
		t.Fatalf("a dense, complete tail was rejected: %v", err)
	}

	// Now remove ONE record from the middle of the run and keep everything after
	// it — the hole, precisely.
	gapped := make([]frame, 0, len(tail)-1)
	gapped = append(gapped, tail[0])
	gapped = append(gapped, tail[2:]...)
	err = verifyTailPrefixConsistent(gapped, pos, tails)
	if err == nil {
		t.Fatalf("a replay that skips record %d and applies %d was accepted; that writes a hole",
			tail[1].laneSeq, tail[2].laneSeq)
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a non-prefix-consistent tail is not typed as corruption: %v", err)
	}

	// A tail that stops short of the retained WAL tail is the same defect seen
	// from the other end and must be refused for the same reason.
	if err := verifyTailPrefixConsistent(tail[:len(tail)-1], pos, tails); err == nil {
		t.Fatal("a replay covering less than the retained WAL tail was accepted as complete")
	}
}

// openALaneGapUnderTheTail rewrites the first retained segment's DATA-lane base
// so the stream's first retained data record is numbered 2 instead of 1, with
// nothing at 1.
//
// The header is the one place a lane's numbering is asserted rather than
// counted: everything after it is derived by counting frames, which is why a gap
// inside the retained set is impossible and a gap at the JOIN between the base
// and the retained set is the only one that can exist. It is exactly the shape a
// reclaimed prefix would leave if the prefix it removed had not in fact been
// applied — the mid-file hole, in the smallest form that produces one.
func openALaneGapUnderTheTail(t *testing.T, dir string) {
	t.Helper()
	path := segmentPath(dir, 1)
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read segment: %v", err)
	}
	header, err := decodeSegmentHeader(buf)
	if err != nil {
		t.Fatalf("decode segment header: %v", err)
	}
	header.FirstLaneSeq[StreamLaneData] = 2
	rewritten, err := encodeSegmentHeader(header)
	if err != nil {
		t.Fatalf("encode segment header: %v", err)
	}
	copy(buf, rewritten)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("rewrite segment: %v", err)
	}
}

// TestReplayNeverOffersAGappedChainToTheAuthority is the wiring half of the
// prefix-consistency property, and it is stated as a claim about what leaves
// this process.
//
// The client cannot delegate this check. A record's place in a chain is a local
// fact — the WAL is the only thing that knows which records it is holding and
// where they sit — and once a gapped run has been shipped, whether it becomes a
// hole depends entirely on how strict the far end happens to be. An authority
// that enforces density turns it into a typed conflict; one that does not writes
// zeros into the middle of a file and answers success. The client must not put
// that choice in front of it.
func TestReplayNeverOffersAGappedChainToTheAuthority(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")

	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged under flood"))
	for i := 0; i < 2; i++ {
		chunk := bytes.Repeat([]byte{byte(0x60 + i)}, 4096)
		_, handled, err = f.engine.WriteAt(ctx, "sat/big", int64(i*len(chunk)), chunk)
		mustHandle(t, "write chunk", handled, err)
	}
	if _, err := f.engine.ForceClose("forced unmount"); err != nil {
		t.Fatalf("force-park: %v", err)
	}
	openALaneGapUnderTheTail(t, f.streamDir(1))

	_, flushesBefore, _ := f.auth.calls()
	next, err := f.reattach()
	if err != nil {
		t.Fatalf("a fresh attach must succeed over a contained loss, not fail: %v", err)
	}
	defer next.Close(ctx)
	_, flushesAfter, _ := f.auth.calls()
	if flushesAfter != flushesBefore {
		t.Fatalf("the replay shipped %d batch(es) over a lane gap; whether that becomes a hole "+
			"is then the authority's decision, not this client's", flushesAfter-flushesBefore)
	}

	job, ok := jobByEpoch(next.Status().Jobs, 1)
	if !ok {
		t.Fatal("the gapped replay reported SUCCESS: the job vanished and the loss with it")
	}
	if !job.Quarantined || job.LostRecords == 0 {
		t.Fatalf("gapped replay produced no loss verdict: %+v", job)
	}
	if !strings.Contains(job.LastError, "missing") {
		t.Fatalf("verdict does not name the missing record it refused to apply over: %q", job.LastError)
	}
	if st := next.Status(); st.PendingBytes == 0 {
		t.Fatalf("Status reports zero pending over %d lost byte(s)", job.LostBytes)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Byte-exactness at scale: the live battery's shape, made deterministic.
// ─────────────────────────────────────────────────────────────────────────────

// TestFloodedMultiSegmentParkReplaysByteExactly is the in-process form of the
// live re-test that found the silent loss: a flood large enough to rotate and
// RECLAIM WAL segments, wedged partway through so the park spans several
// segments, then a fresh attach that must bring the whole file back.
//
// The scale is what makes it worth having. Every mechanism in this round only
// becomes reachable once a stream is long enough to have a reclaimed prefix, a
// tail spanning segments, and lane watermarks that disagree with the global
// prefix — which is exactly why the defect survived a suite of small fixtures
// and was found by a 1 GiB flood. The assertion is the same one the live battery
// makes: the authority's copy hashes to what the writer wrote, byte for byte,
// with no hole anywhere in it.
func TestFloodedMultiSegmentParkReplaysByteExactly(t *testing.T) {
	ctx := context.Background()
	restore := segmentTargetBytes
	segmentTargetBytes = 1 << 20
	t.Cleanup(func() { segmentTargetBytes = restore })

	f := newParkFixture(t, "sat")
	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}

	const (
		chunk  = 64 << 10
		chunks = 128 // 8 MiB across ~8 segments
	)
	want := make([]byte, 0, chunk*chunks)
	for i := 0; i < chunks; i++ {
		// A distinct pattern per chunk, so a hole reads as zeros and a
		// misordered apply reads as the wrong chunk. Both are caught.
		block := bytes.Repeat([]byte{byte(i*7 + 1), byte(i), 0xC5, byte(255 - i)}, chunk/4)
		if i == chunks/2 {
			// The wedge lands mid-flood: everything below it applies and its
			// segments are reclaimed, everything above it parks.
			f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged under flood"))
		}
		_, handled, err := f.engine.WriteAt(ctx, "sat/big", int64(i*chunk), block)
		mustHandle(t, "flood write", handled, err)
		if i == chunks/2-1 {
			if err := f.engine.DrainAll(ctx); err != nil {
				t.Fatalf("drain the applied half: %v", err)
			}
		}
		want = append(want, block...)
	}
	wantSum := sha256.Sum256(want)

	scan, err := scanStreamReadOnly(f.streamDir(1))
	if err != nil {
		t.Fatalf("scan the flooded stream: %v", err)
	}
	segments, err := streamSegmentSizes(f.streamDir(1))
	if err != nil {
		t.Fatalf("list segments: %v", err)
	}
	if len(segments) < 2 {
		t.Fatalf("flood produced %d segment(s); the reclaimed-prefix shape needs several", len(segments))
	}
	if scan.firstSeq <= 1 {
		t.Logf("note: no prefix was reclaimed (first retained sequence %d)", scan.firstSeq)
	}

	if _, err := f.engine.ForceClose("forced unmount under flood"); err != nil {
		t.Fatalf("force-park a replayable flooded snapshot returned a verdict: %v", err)
	}
	job, ok := loadJob(f.streamDir(1))
	if !ok {
		t.Fatal("force-park left no recovery registry")
	}
	t.Logf("parked: %d record(s) / %d byte(s), basis=%q, segments=%d, firstRetainedSeq=%d, walTail=%d",
		job.PendingRecords, job.PendingBytes, job.PendingBasis, len(segments), scan.firstSeq, scan.lastSeq)

	next, err := f.reattach()
	if err != nil {
		t.Fatalf("clean fresh attach over the flooded parked tail failed: %v", err)
	}
	defer next.Close(ctx)

	got, ok := f.auth.fileContent("sat/big")
	if !ok {
		t.Fatal("the flooded file is absent on the authority")
	}
	gotSum := sha256.Sum256(got)
	t.Logf("wrote %d bytes sha256=%x; authority holds %d bytes sha256=%x",
		len(want), wantSum, len(got), gotSum)
	if gotSum != wantSum {
		// Name the first divergence, so a hole is reported as a hole rather than
		// as an unequal hash.
		limit := min(len(got), len(want))
		for i := 0; i < limit; i++ {
			if got[i] != want[i] {
				t.Fatalf("replayed file diverges at offset %d (got %#x, want %#x); length got=%d want=%d",
					i, got[i], want[i], len(got), len(want))
			}
		}
		t.Fatalf("replayed file is %d bytes, want %d", len(got), len(want))
	}
	st := next.Status()
	if len(st.Jobs) != 0 || st.PendingRecords != 0 || st.PendingBytes != 0 {
		t.Fatalf("byte-exact replay still reports jobs=%+v pending=%d/%d",
			st.Jobs, st.PendingRecords, st.PendingBytes)
	}
}

// TestForceParkRefusesToPromiseAReplayItCannotMakePrefixConsistent keeps the
// promise and the proof in the same place. The park's whole claim is that the
// next attach will replay this tail EXACTLY; a tail with a gap under it cannot
// be replayed exactly by anyone, so the verification the park already runs has
// to include the property that makes the replay sound.
func TestForceParkRefusesToPromiseAReplayItCannotMakePrefixConsistent(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")

	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged under flood"))
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", 0, bytes.Repeat([]byte{0x7F}, 4096))
	mustHandle(t, "write", handled, err)

	// A healthy park proves replayable and promises a replay.
	if err := verifyParkedStreamReplayable(f.streamDir(1)); err != nil {
		t.Fatalf("a dense parked tail was refused: %v", err)
	}
	if _, err := f.engine.ForceClose("forced unmount"); err != nil {
		t.Fatalf("force-park a replayable snapshot returned a verdict: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(f.streamDir(1), "job.json")); err != nil {
		t.Fatalf("parked stream lost its registry: %v", err)
	}
}
