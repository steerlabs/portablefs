package writeback

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// The park-then-replay harness.
//
// Every test in this file builds the same live-observed shape structurally: a
// stream whose DATA lane is wedged while its NAMESPACE lane keeps applying, a
// forced unmount that parks the undrained tail, and a clean fresh attach that
// must replay it. The wedge is what makes the shape reachable — it pins the
// GLOBAL applied prefix while the per-lane marks run ahead of it — so it is the
// fixture, not a detail.
// ─────────────────────────────────────────────────────────────────────────────

type parkFixture struct {
	t      *testing.T
	auth   *fakeAuthority
	dir    string
	engine *Engine
}

func newParkFixture(t *testing.T, dirs ...string) *parkFixture {
	t.Helper()
	auth := newFakeAuthority()
	auth.mu.Lock()
	for _, d := range dirs {
		auth.dirs[d] = true
	}
	auth.mu.Unlock()
	stateDir := t.TempDir()
	engine, err := Open(context.Background(), Config{
		StateDir: stateDir, VolumeID: "vol", Branch: "main", Remote: auth,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	return &parkFixture{t: t, auth: auth, dir: stateDir, engine: engine}
}

// reattach opens a fresh engine over the same store with every lane healthy —
// the "clean, fresh attach" the product promises will verify and replay the
// parked tail.
func (f *parkFixture) reattach() (*Engine, error) {
	f.t.Helper()
	f.auth.releaseLaneForTest(StreamLaneData)
	return Open(context.Background(), Config{
		StateDir: f.dir, VolumeID: "vol", Branch: "main", Remote: f.auth,
	})
}

func (f *parkFixture) streamDir(epoch uint64) string {
	return filepath.Join(f.dir, streamDirName(epoch))
}

// appendCraftedApplied installs an APPLIED certificate through the live WAL's
// own append path, so the stream's in-memory and on-disk state stay consistent.
// It is how a test manufactures a REAL exactly-once contradiction — two chain
// digests for one lane watermark — without corrupting the frame layer.
func (f *parkFixture) appendCraftedApplied(frame appliedFrame) {
	f.t.Helper()
	f.engine.mu.Lock()
	w := f.engine.wal
	f.engine.mu.Unlock()
	if w == nil {
		f.t.Fatal("stream WAL is not open")
	}
	if err := w.appendControl(frameApplied, frame); err != nil {
		f.t.Fatalf("append crafted APPLIED certificate: %v", err)
	}
	if err := w.Sync(); err != nil {
		f.t.Fatalf("sync crafted APPLIED certificate: %v", err)
	}
}

func hexDigestOf(b byte) string {
	var d [32]byte
	for i := range d {
		d[i] = b
	}
	return hex.EncodeToString(d[:])
}

func mustHandle(t *testing.T, what string, handled bool, err error) {
	t.Helper()
	if err != nil || !handled {
		t.Fatalf("%s: handled=%v err=%v", what, handled, err)
	}
}

// jobByEpoch finds a reported recovery job.
func jobByEpoch(jobs []RecoveryJob, epoch uint64) (RecoveryJob, bool) {
	for _, j := range jobs {
		if j.WALEpoch == epoch {
			return j, true
		}
	}
	return RecoveryJob{}, false
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. The defect itself: divergent lane marks under a pinned global watermark.
// ─────────────────────────────────────────────────────────────────────────────

// TestDivergentLaneMarksUnderAPinnedGlobalWatermarkStillReplay is the exact
// live failure, constructed deterministically.
//
// A wedged data lane pins the GLOBAL applied prefix at the sequence of its first
// unshipped record. The namespace lane keeps applying in unrelated scopes, and
// every drained scope release writes an APPLIED certificate — so the stream
// accumulates several certificates carrying the SAME global watermark and
// DIFFERENT namespace marks. That is the ordinary steady state of a laned
// stream, and the recovery reader used to condemn it as
//
//	writeback: wal corruption: conflicting applied digests at watermark N
//
// The consequences were the whole defect: the parked tail was never replayed
// (its bytes gone, not partially written), the scope it was written under stayed
// checked out to a dead stream so its directory failed every enumeration on
// every later attach, and the drain accounting reported zero pending over all
// of it.
func TestDivergentLaneMarksUnderAPinnedGlobalWatermarkStillReplay(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat", "keep", "keep2")

	payload := bytes.Repeat([]byte{0xA7}, 4096)
	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain the namespace record that precedes the wedge: %v", err)
	}

	// The wedge. Everything after this pins the global prefix at the write's
	// own sequence while the namespace lane runs on.
	f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged under flood"))
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", 0, payload)
	mustHandle(t, "write sat/big", handled, err)

	// Two drained scope releases, each writing an APPLIED certificate at the
	// pinned global watermark with a different namespace mark.
	_, handled, err = f.engine.Mkdir(ctx, "keep/a", 0o755)
	mustHandle(t, "mkdir keep/a", handled, err)
	if err := f.engine.ReleaseFor(ctx, "keep"); err != nil {
		t.Fatalf("release keep: %v", err)
	}
	_, handled, err = f.engine.Mkdir(ctx, "keep2/b", 0o755)
	mustHandle(t, "mkdir keep2/b", handled, err)
	if err := f.engine.ReleaseFor(ctx, "keep2"); err != nil {
		t.Fatalf("release keep2: %v", err)
	}

	// The fixture must actually have produced the divergent shape, or this test
	// proves nothing.
	scan, err := scanStreamReadOnly(f.streamDir(1))
	if err != nil {
		t.Fatalf("scan parked stream: %v", err)
	}
	_, _, marks, _, err := decodeStreamFrames(scan.frames)
	if err != nil {
		t.Fatalf("decode parked stream: %v", err)
	}
	byGlobal := map[uint64]map[uint64]bool{}
	for _, m := range marks {
		if byGlobal[m.Through] == nil {
			byGlobal[m.Through] = map[uint64]bool{}
		}
		byGlobal[m.Through][m.NSThrough] = true
	}
	divergent := false
	for _, ns := range byGlobal {
		if len(ns) > 1 {
			divergent = true
		}
	}
	if !divergent {
		t.Fatalf("fixture did not produce two namespace marks at one global watermark: %v", byGlobal)
	}

	jobID, err := f.engine.ForceClose("wedged under flood")
	if err != nil {
		t.Fatalf("force-park a healthy stream returned a verdict: %v", err)
	}
	if jobID == "" {
		t.Fatal("force-park produced no job identity")
	}

	next, err := f.reattach()
	if err != nil {
		t.Fatalf("clean fresh attach over the parked tail failed: %v", err)
	}
	defer next.Close(ctx)

	// The promise the product printed, kept.
	if err := f.auth.equalFile("sat/big", payload); err != nil {
		t.Fatalf("the parked tail was not replayed: %v", err)
	}
	st := next.Status()
	if len(st.Jobs) != 0 {
		t.Fatalf("a fully replayed stream left recovery jobs behind: %+v", st.Jobs)
	}
	if st.PendingRecords != 0 || st.PendingBytes != 0 || st.UnrecoveredBytes != 0 {
		t.Fatalf("drained stream reports pending=%d/%d unrecovered=%d",
			st.PendingRecords, st.PendingBytes, st.UnrecoveredBytes)
	}
	if _, err := os.Lstat(f.streamDir(1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replayed stream directory survived: %v", err)
	}
	// The namespace is usable, which is what the held grant used to prevent.
	_, handled, err = next.Mkdir(ctx, "sat/again", 0o755)
	mustHandle(t, "mkdir under the recovered scope", handled, err)
}

// TestLanedStreamWithAnAppliedCertificateReplaysItsForcedParkedTail closes the
// second half of the same defect, which survives even when no two certificates
// disagree.
//
// An APPLIED certificate spells its global watermark in the Through field, and
// a build that also read that field back as the LEGACY LANE's watermark invented
// a legacy tail for every stream born after the lane boundary — a lane with no
// records at all, reported as reaching the global sequence. Recovery then drained
// every real lane to its real tail and parked the stream as corrupt anyway,
// because one phantom lane could never reach a tail it never had.
//
// One certificate is enough to reach it, which is why it is tested apart from
// the divergence case: any forced park of a laned stream that had ever released
// a drained scope was unreplayable.
func TestLanedStreamWithAnAppliedCertificateReplaysItsForcedParkedTail(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat", "keep")

	payload := bytes.Repeat([]byte{0x5C}, 2048)
	_, handled, err := f.engine.Mkdir(ctx, "keep/a", 0o755)
	mustHandle(t, "mkdir keep/a", handled, err)
	_, handled, err = f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	// Exactly one APPLIED certificate, at a nonzero global watermark.
	if err := f.engine.ReleaseFor(ctx, "keep"); err != nil {
		t.Fatalf("release keep: %v", err)
	}
	f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged"))
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", 0, payload)
	mustHandle(t, "write sat/big", handled, err)

	scan, err := scanStreamReadOnly(f.streamDir(1))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	_, _, marks, _, err := decodeStreamFrames(scan.frames)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(marks) == 0 {
		t.Fatal("fixture produced no APPLIED certificate")
	}
	cert, err := highestAppliedCertificate(marks, scan.lastSeq)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	if cert.global == 0 {
		t.Fatal("fixture produced a zero global watermark, which cannot alias")
	}
	if cert.lanes[StreamLaneLegacy].through != 0 {
		t.Fatalf("a stream born laned read back a legacy watermark of %d",
			cert.lanes[StreamLaneLegacy].through)
	}

	if _, err := f.engine.ForceClose("wedged"); err != nil {
		t.Fatalf("force-park a healthy stream returned a verdict: %v", err)
	}
	next, err := f.reattach()
	if err != nil {
		t.Fatalf("clean fresh attach failed: %v", err)
	}
	defer next.Close(ctx)
	if err := f.auth.equalFile("sat/big", payload); err != nil {
		t.Fatalf("the parked tail was not replayed: %v", err)
	}
	if jobs := next.Status().Jobs; len(jobs) != 0 {
		t.Fatalf("replayed stream left jobs behind: %+v", jobs)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. What is still corruption, and what it must cost.
// ─────────────────────────────────────────────────────────────────────────────

// TestHighestAppliedCertificateRejectsTwoDigestsAtOneLaneWatermark pins the
// exactly-once proof that survives the relaxation above. Two certificates may
// disagree about anything except this: one lane watermark names exactly one
// chain digest, because one chain cannot have two values at one position.
func TestHighestAppliedCertificateRejectsTwoDigestsAtOneLaneWatermark(t *testing.T) {
	for _, tc := range []struct {
		name  string
		marks []appliedFrame
		want  string
	}{
		{
			name: "same global watermark, different namespace mark, agreeing chains",
			marks: []appliedFrame{
				{Through: 7, Digest: hexDigestOf(0), NSThrough: 2, NSDigest: hexDigestOf(0xA1)},
				{Through: 7, Digest: hexDigestOf(0), NSThrough: 5, NSDigest: hexDigestOf(0xB2)},
			},
		},
		{
			name: "same namespace watermark, two digests",
			marks: []appliedFrame{
				{Through: 7, Digest: hexDigestOf(0), NSThrough: 5, NSDigest: hexDigestOf(0xA1)},
				{Through: 7, Digest: hexDigestOf(0), NSThrough: 5, NSDigest: hexDigestOf(0xB2)},
			},
			want: "conflicting namespace-lane applied digests at lane watermark 5",
		},
		{
			name: "same data watermark, two digests, reported out of order",
			marks: []appliedFrame{
				{Through: 9, Digest: hexDigestOf(0), DataThrough: 4, DataDigest: hexDigestOf(0xC3)},
				{Through: 3, Digest: hexDigestOf(0), DataThrough: 4, DataDigest: hexDigestOf(0xD4)},
			},
			want: "conflicting data-lane applied digests at lane watermark 4",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := highestAppliedCertificate(tc.marks, 32)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("legitimate certificates rejected: %v", err)
			case tc.want == "":
				// The fold takes the per-lane MAXIMUM, not one frame's snapshot.
				if cert.lanes[StreamLaneNamespace].through != 5 {
					t.Fatalf("namespace lane folded to %d, want the highest proven watermark 5",
						cert.lanes[StreamLaneNamespace].through)
				}
			case err == nil:
				t.Fatalf("a real chain contradiction was accepted: %+v", cert)
			case !errors.Is(err, ErrCorrupt):
				t.Fatalf("contradiction is not typed as corruption: %v", err)
			default:
				if got := err.Error(); !bytes.Contains([]byte(got), []byte(tc.want)) {
					t.Fatalf("verdict %q does not name the offending lane watermark (want %q)", got, tc.want)
				}
			}
		})
	}
}

// TestAppliedCertificateRoundTripsEveryLegacyWatermarkShape pins the three
// readings of the legacy lane's watermark, including the pre-round-7 encoding
// that has no field for it.
func TestAppliedCertificateRoundTripsEveryLegacyWatermarkShape(t *testing.T) {
	nsDigest := [32]byte{1, 2, 3}
	legacyDigest := [32]byte{9, 9, 9}

	t.Run("legacy era round-trips its own watermark", func(t *testing.T) {
		in := legacyStreamMark(11, legacyDigest)
		out, err := in.appliedFrame().mark()
		if err != nil {
			t.Fatal(err)
		}
		if out.global != 11 || out.lanes[StreamLaneLegacy] != (laneMark{11, legacyDigest}) {
			t.Fatalf("legacy round-trip = %+v", out)
		}
	})

	t.Run("a stream born laned keeps an empty legacy lane", func(t *testing.T) {
		var in streamMark
		in.global = 11
		in.lanes[StreamLaneNamespace] = laneMark{through: 11, digest: nsDigest}
		frame := in.appliedFrame()
		if frame.LegacyThrough != 0 {
			t.Fatalf("empty legacy lane encoded a watermark of %d", frame.LegacyThrough)
		}
		out, err := frame.mark()
		if err != nil {
			t.Fatal(err)
		}
		if out.lanes[StreamLaneLegacy].through != 0 {
			t.Fatalf("empty legacy lane read back watermark %d (the global sequence is %d)",
				out.lanes[StreamLaneLegacy].through, out.global)
		}
		if out.lanes[StreamLaneNamespace] != (laneMark{11, nsDigest}) {
			t.Fatalf("namespace lane round-trip = %+v", out.lanes[StreamLaneNamespace])
		}
	})

	t.Run("a stream that crossed the boundary keeps its frozen legacy watermark", func(t *testing.T) {
		var in streamMark
		in.global = 20
		in.lanes[StreamLaneLegacy] = laneMark{through: 4, digest: legacyDigest}
		in.lanes[StreamLaneNamespace] = laneMark{through: 16, digest: nsDigest}
		out, err := in.appliedFrame().mark()
		if err != nil {
			t.Fatal(err)
		}
		if out.lanes[StreamLaneLegacy] != (laneMark{4, legacyDigest}) {
			t.Fatalf("frozen legacy pair round-trip = %+v", out.lanes[StreamLaneLegacy])
		}
	})

	t.Run("a pre-round-7 certificate still reads its watermark from Through", func(t *testing.T) {
		// The exact bytes a pre-lane writer produced: no lane fields at all.
		out, err := appliedFrame{Through: 6, Digest: hex.EncodeToString(legacyDigest[:])}.mark()
		if err != nil {
			t.Fatal(err)
		}
		if out.lanes[StreamLaneLegacy] != (laneMark{6, legacyDigest}) {
			t.Fatalf("pre-round-7 certificate read back %+v", out.lanes[StreamLaneLegacy])
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Containment: an unreplayable job must not take the namespace with it.
// ─────────────────────────────────────────────────────────────────────────────

// wedgeUnreplayableStream builds a stream that is GENUINELY unreplayable: an
// unshipped tail under a held scope, plus two APPLIED certificates that name one
// namespace watermark with two chain digests. It returns the tail's content.
func wedgeUnreplayableStream(t *testing.T, f *parkFixture) []byte {
	t.Helper()
	ctx := context.Background()
	payload := bytes.Repeat([]byte{0x3E}, 4096)
	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.auth.holdLaneForTest(StreamLaneData, errors.New("uplink wedged"))
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", 0, payload)
	mustHandle(t, "write sat/big", handled, err)

	applied := f.engine.fl.appliedState()
	nsThrough := applied.lanes[StreamLaneNamespace].through
	if nsThrough == 0 {
		t.Fatal("fixture has no applied namespace watermark to contradict")
	}
	base := applied.appliedFrame()
	for _, digest := range []string{hexDigestOf(0x11), hexDigestOf(0x22)} {
		contradiction := base
		contradiction.NSThrough = nsThrough
		contradiction.NSDigest = digest
		f.appendCraftedApplied(contradiction)
	}
	return payload
}

// TestUnreplayableParkedJobIsContainedInsteadOfPoisoningTheNamespace is the
// containment contract.
//
// A parked job that cannot be replayed loses its tail — that much is settled by
// the time recovery reaches this point. What must NOT also happen is the live
// outcome: the stream's delegation grants staying checked out to a dead
// writeback identity, so that the covered directory fails every enumeration on
// every subsequent clean attach, forever, with no operator affordance at all. A
// lost tail is a bounded loss; an unusable namespace is an unbounded one.
func TestUnreplayableParkedJobIsContainedInsteadOfPoisoningTheNamespace(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")
	wedgeUnreplayableStream(t, f)

	jobID, err := f.engine.ForceClose("wedged under flood")
	if err == nil {
		t.Fatal("force-park promised a replay for a snapshot it cannot replay")
	}
	if jobID == "" {
		t.Fatal("force-park produced no job identity to report the loss under")
	}

	next, err := f.reattach()
	if err != nil {
		t.Fatalf("a fresh attach must succeed over an unreplayable job, not fail: %v", err)
	}
	defer next.Close(ctx)

	job, ok := jobByEpoch(next.Status().Jobs, 1)
	if !ok {
		t.Fatal("the unreplayable job vanished instead of being reported")
	}
	if !job.Quarantined {
		t.Fatalf("job was left uncontained: %+v", job)
	}
	if job.State != JobCorrupt {
		t.Fatalf("contained job state = %q, want %q", job.State, JobCorrupt)
	}
	if job.LostRecords != 1 || job.LostBytes == 0 {
		t.Fatalf("loss verdict = %d record(s) / %d byte(s), want the exact unshipped tail",
			job.LostRecords, job.LostBytes)
	}
	if !reflect.DeepEqual(job.LostScopes, []string{"sat"}) {
		t.Fatalf("loss verdict names scopes %v, want the scope the lost writes were made under", job.LostScopes)
	}
	if job.Remedy == "" {
		t.Fatal("loss verdict carries no operator remedy")
	}

	// The namespace is given back. Both halves matter: the authority must no
	// longer hold a grant bound to the dead stream, AND this mount must be able
	// to acquire the scope again — which is the difference between a directory
	// that enumerates and one that answers EAGAIN forever.
	if n := f.auth.grantCount(); n != 0 {
		t.Fatalf("%d delegation grant(s) still checked out to the contained stream", n)
	}
	_, handled, err := next.Mkdir(ctx, "sat/again", 0o755)
	mustHandle(t, "mutate under a scope released by containment", handled, err)

	// The bytes are moved out of the scan path, not deleted: they are the only
	// remaining copy of what was acknowledged.
	if _, err := os.Lstat(f.streamDir(1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("contained stream still sits in the recovery scan path: %v", err)
	}
	quarantined := filepath.Join(f.dir, quarantineDirName, streamDirName(1))
	if job.QuarantinePath != quarantined {
		t.Fatalf("verdict points at %q, want %q", job.QuarantinePath, quarantined)
	}
	if _, err := os.Lstat(quarantined); err != nil {
		t.Fatalf("contained stream bytes were not retained: %v", err)
	}
	if segs, _ := filepath.Glob(filepath.Join(quarantined, "wb-*.pfw")); len(segs) == 0 {
		t.Fatal("contained stream retained no WAL segments")
	}
}

// TestContainedJobVerdictSurvivesEveryLaterAttach keeps the loss from becoming
// invisible. A verdict an operator has not acted on must be reported again on
// the next attach, and the next, without ever being retried — a proof does not
// become false by being re-read.
func TestContainedJobVerdictSurvivesEveryLaterAttach(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")
	wedgeUnreplayableStream(t, f)
	if _, err := f.engine.ForceClose("wedged"); err == nil {
		t.Fatal("force-park promised a replay it cannot honor")
	}

	first, err := f.reattach()
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	firstJob, ok := jobByEpoch(first.Status().Jobs, 1)
	if !ok || !firstJob.Quarantined {
		t.Fatalf("first attach did not contain the job: %+v", first.Status().Jobs)
	}
	acquiresBefore := f.auth.acquires
	if err := first.Close(ctx); err != nil {
		t.Fatalf("close first attach: %v", err)
	}
	_ = acquiresBefore

	second, err := f.reattach()
	if err != nil {
		t.Fatalf("second attach over a contained job: %v", err)
	}
	defer second.Close(ctx)
	secondJob, ok := jobByEpoch(second.Status().Jobs, 1)
	if !ok {
		t.Fatal("the contained verdict was not reported on the second attach")
	}
	if !secondJob.Quarantined || secondJob.State != JobCorrupt {
		t.Fatalf("re-reported verdict lost its containment: %+v", secondJob)
	}
	if secondJob.LostRecords != firstJob.LostRecords || secondJob.LostBytes != firstJob.LostBytes {
		t.Fatalf("loss figures drifted across attaches: %d/%d then %d/%d",
			firstJob.LostRecords, firstJob.LostBytes, secondJob.LostRecords, secondJob.LostBytes)
	}
	// A contained stream is never re-attempted, so it never mints a new epoch
	// collision or a second quarantine slot.
	entries, err := os.ReadDir(filepath.Join(f.dir, quarantineDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("quarantine holds %d entries, want exactly the one contained stream", len(entries))
	}
}

// TestForeignParkedStreamIsReportedButNeverContained guards the one terminal
// verdict containment must not touch. A stream belonging to another volume or
// branch is not this engine's to sweep or move — its grants belong to a
// different ledger entirely.
func TestForeignParkedStreamIsReportedButNeverContained(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")
	_, handled, err := f.engine.Create(ctx, "sat/file", 0o644, false, false)
	mustHandle(t, "create sat/file", handled, err)
	f.engine.Abandon()

	// Reattach the same store under a different branch identity.
	f.auth.releaseLaneForTest(StreamLaneData)
	next, err := Open(ctx, Config{
		StateDir: f.dir, VolumeID: "vol", Branch: "other", Remote: f.auth,
	})
	if err != nil {
		t.Fatalf("attach with a foreign parked stream present: %v", err)
	}
	defer next.Close(ctx)
	job, ok := jobByEpoch(next.Status().Jobs, 1)
	if !ok {
		t.Fatal("foreign stream was not reported")
	}
	if job.Quarantined {
		t.Fatalf("foreign stream was contained: %+v", job)
	}
	if job.State != JobConflict {
		t.Fatalf("foreign stream state = %q, want %q", job.State, JobConflict)
	}
	if _, err := os.Lstat(f.streamDir(1)); err != nil {
		t.Fatalf("foreign stream bytes were moved: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Honest accounting.
// ─────────────────────────────────────────────────────────────────────────────

// TestFailedReplayKeepsDrainAccountingHonest closes the zero-pending lie.
//
// Live, a fresh attach over an unreplayable 156 MiB tail reported pendingBytes
// of zero, so every drain-to-zero check in the product answered "drained" over
// data that was in fact unrecoverable. Acknowledged bytes that are locally
// durable and not at the authority are pending, whoever admitted them and
// whether or not they can still be replayed — and they stay pending until an
// operator clears the containment.
func TestFailedReplayKeepsDrainAccountingHonest(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")
	wedgeUnreplayableStream(t, f)
	if _, err := f.engine.ForceClose("wedged"); err == nil {
		t.Fatal("force-park promised a replay it cannot honor")
	}

	next, err := f.reattach()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer next.Close(ctx)

	job, ok := jobByEpoch(next.Status().Jobs, 1)
	if !ok || !job.Quarantined {
		t.Fatalf("fixture did not produce a contained job: %+v", next.Status().Jobs)
	}
	if job.LostBytes == 0 {
		t.Fatal("fixture lost nothing, so there is no lie to test")
	}

	records, bytes := next.Pending()
	if records == 0 || bytes == 0 {
		t.Fatalf("Pending() reports %d record(s) / %d byte(s) while %d unrecoverable byte(s) sit on disk",
			records, bytes, job.LostBytes)
	}
	if uint64(bytes) < job.LostBytes {
		t.Fatalf("Pending() reports %d byte(s), fewer than the %d byte(s) known lost", bytes, job.LostBytes)
	}
	st := next.Status()
	if st.UnrecoveredRecords != job.LostRecords || st.UnrecoveredBytes != job.LostBytes {
		t.Fatalf("Status unrecovered = %d/%d, want the contained job's %d/%d",
			st.UnrecoveredRecords, st.UnrecoveredBytes, job.LostRecords, job.LostBytes)
	}
	if st.PendingBytes < int64(st.UnrecoveredBytes) {
		t.Fatalf("Status pendingBytes %d excludes the %d unrecovered byte(s)",
			st.PendingBytes, st.UnrecoveredBytes)
	}

	// A full local drain of the LIVE stream must not flip the store to
	// "drained" while the contained bytes are still there.
	_, handled, err := next.Mkdir(ctx, "sat/again", 0o755)
	mustHandle(t, "mkdir sat/again", handled, err)
	if err := next.DrainAll(ctx); err != nil {
		t.Fatalf("drain the live stream: %v", err)
	}
	records, bytes = next.Pending()
	if records == 0 || bytes == 0 {
		t.Fatalf("a fully drained LIVE stream reported the whole store drained while %d contained byte(s) remain",
			job.LostBytes)
	}
}

// TestParkedButUndrainedJobCountsAsPending is the same honesty rule for the
// ordinary case: a job that is merely parked and not yet replayed is durable
// debt too, and a status that omits it is the same lie one step earlier.
func TestParkedButUndrainedJobCountsAsPending(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")
	payload := bytes.Repeat([]byte{0x77}, 4096)
	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.engine.mu.Lock()
	job := f.engine.job
	f.engine.mu.Unlock()
	if job == nil {
		t.Fatal("no recovery registry")
	}
	f.auth.holdLaneForTest(StreamLaneData, errors.New("wedged"))
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", 0, payload)
	mustHandle(t, "write sat/big", handled, err)
	if _, err := f.engine.ForceClose("wedged"); err != nil {
		t.Fatalf("force-park: %v", err)
	}

	// Attach with the lane STILL wedged: recovery cannot drain the tail, so the
	// attach fails as an attach-readiness gate — but the store's own accounting
	// of the parked job must already be honest before then.
	runner := newRecoveryRunner(&Engine{cfg: Config{StateDir: f.dir}, remote: f.auth})
	runner.discover()
	records, bytes := runner.unrecovered()
	if records == 0 || bytes == 0 {
		t.Fatalf("a parked, undrained job contributes %d record(s) / %d byte(s) of debt", records, bytes)
	}
	_ = ctx
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. The park's own promise.
// ─────────────────────────────────────────────────────────────────────────────

// TestForceCloseRefusesToPromiseAReplayItCannotHonor is requirement (2): the
// forced-unmount message is a durability promise, so the snapshot behind it is
// proved before the promise is published, and when it cannot be proved the park
// says so DEFINITELY instead.
func TestForceCloseRefusesToPromiseAReplayItCannotHonor(t *testing.T) {
	f := newParkFixture(t, "sat")
	wedgeUnreplayableStream(t, f)

	jobID, err := f.engine.ForceClose("forced unmount")
	if err == nil {
		t.Fatal("an unreplayable snapshot was parked as a replay promise")
	}
	if !errors.Is(err, ErrParkNotReplayable) {
		t.Fatalf("verdict is not the typed definite answer: %v", err)
	}
	if jobID == "" {
		t.Fatal("the verdict carries no job identity to report it under")
	}
	// The teardown still completed: a forced unmount is invoked because the
	// mount must go away, so a verdict must not also leave it wedged.
	f.engine.mu.Lock()
	closed := f.engine.closed
	f.engine.mu.Unlock()
	if !closed {
		t.Fatal("forced unmount returned a verdict without completing its teardown")
	}
	// And the durable job says "lost", not "will replay", from the moment it
	// lands — including across a crash before the next attach.
	durable, ok := loadJob(f.streamDir(1))
	if !ok {
		t.Fatal("no durable recovery registry")
	}
	if durable.State == JobForced {
		t.Fatalf("the durable job still promises a replay: %+v", durable)
	}
	if durable.State != JobCorrupt {
		t.Fatalf("durable job state = %q, want %q", durable.State, JobCorrupt)
	}
	if durable.LastError == "" {
		t.Fatal("the durable job records no reason")
	}
}

// TestForceCloseParksAReplayableSnapshotWithoutAVerdict is the other half: the
// proof must not be a tax on the healthy path. A wedged-but-sound stream parks
// exactly as before, with a job that promises a replay and delivers one.
func TestForceCloseParksAReplayableSnapshotWithoutAVerdict(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")
	payload := bytes.Repeat([]byte{0x19}, 8192)
	_, handled, err := f.engine.Create(ctx, "sat/big", 0o644, false, false)
	mustHandle(t, "create sat/big", handled, err)
	if err := f.engine.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.auth.holdLaneForTest(StreamLaneData, errors.New("wedged"))
	_, handled, err = f.engine.WriteAt(ctx, "sat/big", 0, payload)
	mustHandle(t, "write sat/big", handled, err)

	jobID, err := f.engine.ForceClose("forced unmount")
	if err != nil {
		t.Fatalf("a replayable snapshot was refused: %v", err)
	}
	durable, ok := loadJob(f.streamDir(1))
	if !ok || durable.State != JobForced || durable.JobID != jobID {
		t.Fatalf("durable job = %+v (id %q)", durable, jobID)
	}
	next, err := f.reattach()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer next.Close(ctx)
	if err := f.auth.equalFile("sat/big", payload); err != nil {
		t.Fatalf("the promised replay did not happen: %v", err)
	}
}

// TestVerifyParkedStreamReplayableNamesWhatIsWrong keeps the verdict specific.
// "Cannot replay" without a reason is not a verdict an operator can act on.
func TestVerifyParkedStreamReplayableNamesWhatIsWrong(t *testing.T) {
	f := newParkFixture(t, "sat")
	wedgeUnreplayableStream(t, f)
	f.engine.mu.Lock()
	dir := f.engine.wal.Dir()
	f.engine.mu.Unlock()
	err := verifyParkedStreamReplayable(dir)
	if err == nil {
		t.Fatal("an unreplayable stream verified clean")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("verdict is not typed as corruption: %v", err)
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("lane watermark")) {
		t.Fatalf("verdict %q does not say what contradicts what", got)
	}
	_ = fmt.Sprint(err)
}
