package writeback

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// releaseBlockedAuthority makes the authority side of the close-out fail on
// demand AFTER the local RELEASE certificate is durable. That is the only
// window in which the certificate's own byte cost is observable: on success
// recovery removes the stream directory.
type releaseBlockedAuthority struct {
	*fakeAuthority
	blocked atomic.Bool
}

func (a *releaseBlockedAuthority) ReleaseDelegation(ctx context.Context, scope, epoch string) error {
	if a.blocked.Load() {
		return errors.New("fake: authority unreachable for release")
	}
	return a.fakeAuthority.ReleaseDelegation(ctx, scope, epoch)
}

// seedLegacyGrants installs the fixture's grants on the authority exactly as a
// pre-upgrade holder would have left them: still checked out to this stream.
func seedLegacyGrants(auth *fakeAuthority, wbID string, scopes map[string]string) {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	for scope, epoch := range scopes {
		auth.dirs[scope] = true
		auth.grants[scope] = fakeGrant{epoch: epoch, wbID: wbID}
	}
	if _, ok := auth.streams[wbID]; !ok {
		auth.streams[wbID] = newFakeStream()
	}
}

// TestLegacyOversizedEpochStreamReachesADefiniteRelease is FINDING 4.
//
// A pre-81e235b holder recorded an authority epoch longer than the 256-byte
// admission cap introduced later. The frame is perfectly valid under the frozen
// PFW5 decoder, so recovery replays the stream — but the RELEASE certificate
// re-encodes that already-accepted epoch through the admission encoder, which
// now refuses it. The stream becomes replayable-forever and never releasable:
// an unbounded errRetryable loop that fails every attach.
func TestLegacyOversizedEpochStreamReachesADefiniteRelease(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	mountID, err := ensureMountID(stateDir)
	if err != nil {
		t.Fatalf("mount identity: %v", err)
	}
	legacyEpoch := strings.Repeat("E", maxEpochBytes+64)

	s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
	s.delegation("d", legacyEpoch)
	s.mutation(wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644})
	s.mutation(wal.Record{Op: wal.OpWrite, Path: "d/f", Data: []byte("legacy tail")})
	s.finish()

	auth := newFakeAuthority()
	seedLegacyGrants(auth, streamID(mountID, 1), map[string]string{"d": legacyEpoch})

	e, err := Open(ctx, Config{
		StateDir: stateDir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("attach with a legacy oversized-epoch stream parked: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()

	if err := auth.equalFile("d/f", []byte("legacy tail")); err != nil {
		t.Fatalf("legacy tail did not reach the authority: %v", err)
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("recovery left %d grants held on the authority", got)
	}
	if jobs := e.Status().Jobs; len(jobs) != 0 {
		t.Fatalf("recovery left jobs registered: %+v", jobs)
	}
	if _, err := os.Stat(filepath.Join(stateDir, streamDirName(1))); !os.IsNotExist(err) {
		t.Fatalf("recovered legacy stream directory was not removed (%v)", err)
	}
}

// appliedMarkCost is the exact on-disk cost of one close-out APPLIED mark. The
// digest is always 64 hex characters, so only the decimal watermark varies;
// costing it at the maximum watermark is an upper bound within a few bytes.
//
// It is the headroom the PEAK-bounded close-out protocol requires. Barrier A
// appends the mark BEFORE the reclaim — it has to, because digestAt cannot
// rebuild a digest across segments that are already gone — so the transient
// occupancy peak is used+appliedBytes, and a stream with literally zero bytes to
// spare cannot close out at all. That is now a definite typed conflict
// (CLOSE_OUT_UNBOUNDED) rather than a transient overshoot of the hard cap.
func appliedMarkCost(t *testing.T) int64 {
	t.Helper()
	payload, err := encodeControlPayload(appliedFrame{
		Through: ^uint64(0),
		Digest:  fmt.Sprintf("%x", [32]byte{}),
	})
	if err != nil {
		t.Fatalf("cost the close-out applied mark: %v", err)
	}
	return frameLen(len(payload))
}

// TestLegacyStreamAtTheCapClosesOutInsideTheBound is FINDING 5.
//
// A pre-upgrade stream may occupy the whole configured cap: no control reserve
// existed when it was written. appendRecoveryReleaseCertificate then raw-appends
// APPLIED plus one RELEASE per live grant with no budget arithmetic at all, so
// the close-out pushes the stream past the bound it claims to enforce (and, on a
// real store at its cap, into a mid-append physical ENOSPC).
//
// The stream is filled to one applied-mark short of the cap rather than to the
// last byte: that is the tightest shape the peak-bounded protocol can still
// close out, and it is the shape under test — everything past it is the typed
// terminal conflict, which TestLegacyCloseOutBeyondTheCapIsTerminalNotRetryable
// and the peak tests own.
func TestLegacyStreamAtTheCapClosesOutInsideTheBound(t *testing.T) {
	const budget = 256 << 10
	markCost := appliedMarkCost(t)
	// The in-cap shape isolates FINDING 5 from FINDING 4: every epoch would be
	// admissible today, so the ONLY thing that can push the stream past its cap
	// is the unbudgeted certificate append itself.
	for _, tc := range []struct {
		name       string
		epochBytes int
	}{
		{"epochs within the admission caps", 8},
		{"legacy epochs past the admission caps", 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			stateDir := t.TempDir()
			mountID, err := ensureMountID(stateDir)
			if err != nil {
				t.Fatalf("mount identity: %v", err)
			}

			grants := map[string]string{}
			s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
			for i := 0; i < 4; i++ {
				scope := fmt.Sprintf("s%d", i)
				epoch := strings.Repeat(fmt.Sprintf("%d", i), tc.epochBytes)
				grants[scope] = epoch
				s.delegation(scope, epoch)
			}
			// Take the stream to within one applied mark of the cap, as a
			// pre-upgrade mutation lane could: nothing was held back for
			// close-out because no control reserve existed, and this is the
			// tightest stream a peak-bounded close-out can still resolve.
			s.fillToCap(budget-markCost, 1024)
			s.finish()

			dir := filepath.Join(stateDir, streamDirName(1))
			before := streamFootprint(t, dir)
			if before > budget {
				t.Fatalf("fixture built a %d-byte stream, past its own %d-byte cap", before, budget)
			}
			if segs := streamSegmentCount(t, dir); segs < 2 {
				t.Fatalf("fixture did not span multiple segments (%d)", segs)
			}

			auth := &releaseBlockedAuthority{fakeAuthority: newFakeAuthority()}
			auth.blocked.Store(true)
			seedLegacyGrants(auth.fakeAuthority, streamID(mountID, 1), grants)

			// The authority release fails, so recovery stops with the local
			// RELEASE certificate already durable — the only state in which the
			// certificate's byte cost is observable (a successful recovery
			// removes the whole directory).
			cfg := Config{StateDir: stateDir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: budget}
			if _, err := Open(ctx, cfg); err == nil {
				t.Fatal("attach succeeded while every authority release was failing")
			}
			after := streamFootprint(t, dir)
			if after > budget {
				t.Fatalf("the recovery close-out drove the legacy stream to %d bytes, past its %d-byte cap (was %d)",
					after, budget, before)
			}
			if _, err := scanStreamReadOnly(dir); err != nil {
				t.Fatalf("the stream no longer replays after the close-out append: %v", err)
			}

			// The accommodation must be crash-safe, not merely small: the
			// reduced stream has to recover to completion on the next attach.
			auth.blocked.Store(false)
			e, err := Open(ctx, cfg)
			if err != nil {
				t.Fatalf("second attach after the budgeted close-out: %v", err)
			}
			defer func() { _, _ = e.ForceClose("teardown") }()
			if got := auth.grantCount(); got != 0 {
				t.Fatalf("recovery left %d grants held on the authority", got)
			}
			if jobs := e.Status().Jobs; len(jobs) != 0 {
				t.Fatalf("recovery left jobs registered: %+v", jobs)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("recovered legacy stream directory was not removed (%v)", err)
			}
		})
	}
}

// TestLegacyCloseOutBeyondTheCapIsTerminalNotRetryable pins the other half of
// the definite-outcome claim. When the certificate cannot be made to fit even
// after the accommodation, recovery must land in a typed terminal state that a
// mount surfaces once — never an unbounded retry that fails every attach, and
// never an append that exceeds the bound anyway.
func TestLegacyCloseOutBeyondTheCapIsTerminalNotRetryable(t *testing.T) {
	ctx := context.Background()
	const budget = 32 << 10
	stateDir := t.TempDir()
	mountID, err := ensureMountID(stateDir)
	if err != nil {
		t.Fatalf("mount identity: %v", err)
	}

	grants := map[string]string{}
	s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
	for i := 0; i < 4; i++ {
		scope := fmt.Sprintf("s%d", i)
		epoch := strings.Repeat(fmt.Sprintf("%d", i), 4096)
		grants[scope] = epoch
		s.delegation(scope, epoch)
	}
	s.mutation(wal.Record{Op: wal.OpCreate, Path: "s0/f", Mode: 0o644})
	s.finish()
	dir := filepath.Join(stateDir, streamDirName(1))
	before := streamFootprint(t, dir)

	auth := newFakeAuthority()
	seedLegacyGrants(auth, streamID(mountID, 1), grants)

	e, err := Open(ctx, Config{
		StateDir: stateDir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: budget,
	})
	if err != nil {
		t.Fatalf("a terminal legacy close-out must be surfaced, not fail the attach: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()

	jobs := e.Status().Jobs
	if len(jobs) != 1 {
		t.Fatalf("want exactly one surfaced recovery job, got %+v", jobs)
	}
	if jobs[0].State != JobConflict {
		t.Fatalf("want a typed terminal conflict, got state %q (%s)", jobs[0].State, jobs[0].LastError)
	}
	if after := streamFootprint(t, dir); after > before {
		t.Fatalf("a refused close-out still wrote %d bytes", after-before)
	}
	if _, err := scanStreamReadOnly(dir); err != nil {
		t.Fatalf("the refused close-out left the stream unreplayable: %v", err)
	}
}

// TestStaleAppliedMarkDoesNotAuthorizeTheReclaim closes the trap inside the
// legacy accommodation itself. An APPLIED mark for exactly the drained tail may
// already be durable from an earlier interrupted close-out — but if it sits in a
// segment the reclaim is about to DELETE, it authorizes nothing: the retained
// stream would have no mark to rebuild its digest from and the next attach would
// fail closed as corrupt. The close-out must place a fresh mark in the RETAINED
// segment before it deletes anything.
func TestStaleAppliedMarkDoesNotAuthorizeTheReclaim(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	mountID, err := ensureMountID(stateDir)
	if err != nil {
		t.Fatalf("mount identity: %v", err)
	}
	s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
	s.segmentTarget = 8 << 10
	s.delegation("s0", "epoch-0")
	for i := 0; i < 48; i++ {
		s.mutation(wal.Record{
			Op: wal.OpWrite, Path: fmt.Sprintf("s0/f%03d", i), Data: make([]byte, 512),
		})
	}
	// The mark lands in a segment that is NOT the tail: the rotation after it
	// carries only the re-emitted delegation set, so the tail sequence is
	// unchanged and the mark still names it exactly.
	s.applied(s.seq, s.digest)
	s.rotate()
	tailSeq, tailDigest := s.seq, s.digest
	s.finish()

	dir := filepath.Join(stateDir, streamDirName(1))
	// Exactly the applied mark's room and not one byte more. That still forces
	// the accommodation — the RELEASE frames do not fit — and it expresses the
	// peak invariant directly: barrier A's append is the transient peak, so a
	// close-out is possible iff the stream has at least the mark's headroom.
	budget := streamFootprint(t, dir) + appliedMarkCost(t)
	if streamSegmentCount(t, dir) < 3 {
		t.Fatalf("fixture did not put the mark below the tail segment (%d segments)", streamSegmentCount(t, dir))
	}

	auth := &releaseBlockedAuthority{fakeAuthority: newFakeAuthority()}
	auth.blocked.Store(true)
	seedLegacyGrants(auth.fakeAuthority, streamID(mountID, 1), map[string]string{"s0": "epoch-0"})

	cfg := Config{StateDir: stateDir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: budget}
	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("attach succeeded while every authority release was failing")
	}
	if after := streamFootprint(t, dir); after > budget {
		t.Fatalf("the close-out drove the stream to %d bytes, past its %d-byte cap", after, budget)
	}
	if segs := streamSegmentCount(t, dir); segs != 1 {
		t.Fatalf("the close-out did not reclaim the applied prefix (%d segments left)", segs)
	}
	// The invariant the ordering exists for: whatever the reclaim left behind
	// must still be able to rebuild the stream digest at its tail. That is what
	// every later attach — including one that crashes before the RELEASE frames
	// land — depends on.
	reduced, err := scanStreamReadOnly(dir)
	if err != nil {
		t.Fatalf("the reclaimed stream no longer replays: %v", err)
	}
	if reduced.lastSeq != tailSeq {
		t.Fatalf("the reclaimed stream reports tail %d, want %d", reduced.lastSeq, tailSeq)
	}
	_, _, marks, _, err := decodeStreamFrames(reduced.frames)
	if err != nil {
		t.Fatalf("decode reclaimed stream: %v", err)
	}
	got, err := digestAt(reduced, marks, reduced.lastSeq)
	if err != nil {
		t.Fatalf("the reclaimed stream cannot rebuild the digest at its tail: %v", err)
	}
	if got != tailDigest {
		t.Fatalf("the reclaimed stream rebuilt digest %x at its tail, want %x", got, tailDigest)
	}

	auth.blocked.Store(false)
	e, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("second attach after the reclaim: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()
	if jobs := e.Status().Jobs; len(jobs) != 0 {
		t.Fatalf("the reclaimed stream did not resolve: %+v", jobs)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("recovered stream directory was not removed (%v)", err)
	}
}

// TestReclaimedCloseOutPrefixIsCrashSafe pins the ORDERING that makes the legacy
// accommodation safe rather than hopeful. Barrier A (the APPLIED mark) is what
// authorizes barrier B (deleting the applied segment prefix); a crash between B
// and C leaves a stream with a reclaimed prefix, and that stream must still
// reach a definite outcome. With the mark it releases and resolves; WITHOUT it
// the digest at the tail is no longer derivable and recovery must fail closed as
// corrupt rather than guess.
func TestReclaimedCloseOutPrefixIsCrashSafe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		writeMark bool
	}{
		{"mark written before the reclaim", true},
		{"reclaim without the authorizing mark", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			stateDir := t.TempDir()
			mountID, err := ensureMountID(stateDir)
			if err != nil {
				t.Fatalf("mount identity: %v", err)
			}
			epoch := strings.Repeat("E", maxEpochBytes+64)
			s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
			s.segmentTarget = 8 << 10
			s.delegation("s0", epoch)
			for i := 0; i < 64; i++ {
				s.mutation(wal.Record{
					Op: wal.OpWrite, Path: fmt.Sprintf("s0/f%03d", i), Data: make([]byte, 512),
				})
			}
			if tc.writeMark {
				s.applied(s.seq, s.digest)
			}
			lastSeq, tailDigest := s.seq, s.digest
			s.finish()
			dir := filepath.Join(stateDir, streamDirName(1))
			if streamSegmentCount(t, dir) < 2 {
				t.Fatal("fixture did not span multiple segments")
			}
			reclaimSegmentPrefix(t, dir)

			// The whole tail is already applied at the authority: that is the
			// precondition under which the reclaim was allowed to happen.
			wbID := streamID(mountID, 1)
			auth := newFakeAuthority()
			seedLegacyGrants(auth, wbID, map[string]string{"s0": epoch})
			auth.mu.Lock()
			auth.streams[wbID] = newFakeStreamAt(lastSeq, tailDigest)
			auth.mu.Unlock()

			e, err := Open(ctx, Config{
				StateDir: stateDir, VolumeID: "vol", Branch: "main",
				Remote: auth, BudgetBytes: 1 << 30,
			})
			if err != nil {
				t.Fatalf("attach over a reclaimed close-out prefix: %v", err)
			}
			defer func() { _, _ = e.ForceClose("teardown") }()

			jobs := e.Status().Jobs
			if !tc.writeMark {
				if len(jobs) != 1 || jobs[0].State != JobCorrupt {
					t.Fatalf("a reclaim without its authorizing mark must fail closed as corrupt, got %+v", jobs)
				}
				return
			}
			if len(jobs) != 0 {
				t.Fatalf("recovery left jobs registered: %+v", jobs)
			}
			if got := auth.grantCount(); got != 0 {
				t.Fatalf("recovery left %d grants held on the authority", got)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("recovered stream directory was not removed (%v)", err)
			}
		})
	}
}
