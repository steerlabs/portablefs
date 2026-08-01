package writeback

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// closeOutProbe watches the legacy close-out through its own append seam.
//
// BudgetBytes bounds the stream's OCCUPANCY, not its final footprint: a WAL that
// momentarily exceeds the cap has already exceeded it, and on a store sized to
// the cap that moment is a physical ENOSPC in the middle of the protocol. The
// close-out's reclaim path frees space only at barrier B, so the interesting
// instant is the completion of barrier A — the mark is durable while every
// segment it authorizes deleting is still on disk. The probe samples the
// directory immediately before and immediately after every append, which is
// sufficient because appends are the only thing that grows the stream: the
// maximum over those samples is the true peak.
//
// failAt turns the seam into a fault injector: the named 1-based append returns
// exactly what pwrite(2) gives a caller on a full filesystem, wrapped the way
// appendStreamTailFrames wraps its own write error.
type closeOutProbe struct {
	t      *testing.T
	dir    string
	peak   int64
	calls  int
	failAt int
}

func installCloseOutProbe(t *testing.T, dir string, failAt int) *closeOutProbe {
	t.Helper()
	p := &closeOutProbe{t: t, dir: dir, failAt: failAt}
	p.observe()
	prev := writeStreamTailFrames
	writeStreamTailFrames = func(path string, off int64, body []byte) error {
		p.calls++
		if p.failAt == p.calls {
			return fmt.Errorf("append recovery release certificate: %w", syscall.ENOSPC)
		}
		p.observe()
		err := prev(path, off, body)
		p.observe()
		return err
	}
	t.Cleanup(func() { writeStreamTailFrames = prev })
	return p
}

func (p *closeOutProbe) observe() {
	p.t.Helper()
	if now := streamFootprint(p.t, p.dir); now > p.peak {
		p.peak = now
	}
}

// closeOutScopes is the rebound scope set a close-out is asked to make final,
// in the order recoverStream produces it.
func closeOutScopes(live map[string]string) []RebindScope {
	scopes := make([]RebindScope, 0, len(live))
	for scope, epoch := range live {
		scopes = append(scopes, RebindScope{Scope: scope, Epoch: epoch})
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Scope < scopes[j].Scope })
	return scopes
}

// closeOutCost reproduces the certificate's EXACT byte cost the way the
// close-out computes it: the admission encoder for the freshly computed mark,
// the durable encoder for scopes this stream already accepted once.
func closeOutCost(t *testing.T, scan *streamScan, digest [32]byte, scopes []RebindScope) (appliedBytes, releaseBytes int64) {
	t.Helper()
	appliedPayload, err := encodeControlPayload(appliedFrame{
		Through: scan.lastSeq, Digest: fmt.Sprintf("%x", digest),
	})
	if err != nil {
		t.Fatalf("encode applied payload: %v", err)
	}
	appliedBytes = frameLen(len(appliedPayload))
	for _, sc := range scopes {
		payload, err := encodeDurableControlPayload(delegationFrame{Scope: sc.Scope, Epoch: sc.Epoch})
		if err != nil {
			t.Fatalf("encode release payload for %q: %v", sc.Scope, err)
		}
		releaseBytes += frameLen(len(payload))
	}
	return appliedBytes, releaseBytes
}

// reclaimableBytes is what barrier B would free: every segment but the tail.
func reclaimableBytes(t *testing.T, dir string) int64 {
	t.Helper()
	segments, err := streamSegmentSizes(dir)
	if err != nil {
		t.Fatalf("segment sizes: %v", err)
	}
	var reclaimable int64
	for _, seg := range segments[:len(segments)-1] {
		reclaimable += seg.size
	}
	return reclaimable
}

// streamBytes is the stream's entire on-disk content, keyed by segment name. A
// refused close-out must leave this byte-identical: "returns an error" is not
// the claim, "wrote nothing" is.
func streamBytes(t *testing.T, dir string) map[string]string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "wb-*.pfw"))
	if err != nil {
		t.Fatalf("glob segments: %v", err)
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read segment %s: %v", filepath.Base(name), err)
		}
		out[filepath.Base(name)] = string(body)
	}
	return out
}

func countAppliedFrames(t *testing.T, dir string) int {
	t.Helper()
	scan, err := scanStreamReadOnly(dir)
	if err != nil {
		t.Fatalf("rescan stream: %v", err)
	}
	n := 0
	for _, fr := range scan.frames {
		if fr.typ == frameApplied {
			n++
		}
	}
	return n
}

// atCapLegacyStream builds a pre-upgrade stream that occupies essentially the
// whole cap, the shape a mutation lane with no control reserve could leave
// behind. Its post-reclaim footprint fits comfortably, so ONLY the transient
// peak of barrier A can disqualify it.
func atCapLegacyStream(t *testing.T, budget int64) (dir string, scan *streamScan, digest [32]byte, scopes []RebindScope) {
	t.Helper()
	stateDir := t.TempDir()
	mountID, err := ensureMountID(stateDir)
	if err != nil {
		t.Fatalf("mount identity: %v", err)
	}
	s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
	for i := 0; i < 4; i++ {
		s.delegation(fmt.Sprintf("s%d", i), strings.Repeat(fmt.Sprintf("%d", i), 8))
	}
	s.fillToCap(budget, 1024)
	scan = s.finish()
	return filepath.Join(stateDir, streamDirName(1)), scan, s.digest, closeOutScopes(s.live)
}

// reclaimablyLegacyStream builds a stream that CANNOT take the fast path (its
// oversized legacy epochs make the RELEASE frames too fat for the remaining
// headroom) but whose marker peak fits with room to spare. This is the shape the
// reclaim path exists to serve, and it must keep working unchanged.
func reclaimablyLegacyStream(t *testing.T, budget int64) (dir string, scan *streamScan, digest [32]byte, scopes []RebindScope) {
	t.Helper()
	stateDir := t.TempDir()
	mountID, err := ensureMountID(stateDir)
	if err != nil {
		t.Fatalf("mount identity: %v", err)
	}
	s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
	for i := 0; i < 4; i++ {
		s.delegation(fmt.Sprintf("s%d", i), strings.Repeat(fmt.Sprintf("%d", i), 4096))
	}
	// Stop short of the cap by less than the RELEASE frames cost: the mark fits,
	// the whole certificate does not.
	s.fillToCap(budget-(8<<10), 1024)
	scan = s.finish()
	return filepath.Join(stateDir, streamDirName(1)), scan, s.digest, closeOutScopes(s.live)
}

// TestLegacyCloseOutPeakStaysWithinBudget is the peak-occupancy claim.
//
// The reclaim path's gate only ever checked the POST-reclaim footprint, but the
// protocol reaches that footprint by first appending the barrier-A mark while
// every segment the reclaim will delete is still present. For an at-cap legacy
// stream that intermediate state is `used + appliedBytes`, which is over the cap
// by construction — the WAL exceeds the bound it advertises, and on a store sized
// to that bound the append itself is the thing that runs out of space.
//
// The bound must therefore be decided on the PEAK, before the first byte is
// written, and the answer must be the same definite terminal answer the
// post-reclaim gate already gives.
func TestLegacyCloseOutPeakStaysWithinBudget(t *testing.T) {
	t.Run("at-cap stream cannot afford the marker's transient peak", func(t *testing.T) {
		const budget = 256 << 10
		dir, scan, digest, scopes := atCapLegacyStream(t, budget)

		used := streamFootprint(t, dir)
		appliedBytes, releaseBytes := closeOutCost(t, scan, digest, scopes)
		reclaimable := reclaimableBytes(t, dir)
		if used > budget {
			t.Fatalf("fixture built a %d-byte stream, past its own %d-byte cap", used, budget)
		}
		if used+appliedBytes <= budget {
			t.Fatalf("fixture is not at the cap: peak %d fits the %d-byte budget, nothing to prove",
				used+appliedBytes, budget)
		}
		// The old gate's two conditions both hold, so it takes the reclaim path
		// and writes barrier A. That is precisely the overshoot.
		if reclaimable < appliedBytes {
			t.Fatalf("fixture has %d reclaimable bytes, under the %d-byte mark", reclaimable, appliedBytes)
		}
		if final := used - reclaimable + appliedBytes + releaseBytes; final > budget {
			t.Fatalf("fixture's post-reclaim footprint %d already exceeds %d; the peak is not what is being tested",
				final, budget)
		}

		probe := installCloseOutProbe(t, dir, 0)
		err := appendRecoveryReleaseCertificate(dir, scan, scan.lastSeq, digest, scopes, budget)
		probe.observe()

		if probe.peak > budget {
			t.Fatalf("close-out peaked at %d bytes, past the %d-byte budget (started at %d, %d-byte mark)",
				probe.peak, budget, used, appliedBytes)
		}
		if !errors.Is(err, errCloseOutUnbounded) {
			t.Fatalf("a close-out whose peak cannot fit must be the definite typed answer, got %v", err)
		}
		if after := streamFootprint(t, dir); after != used {
			t.Fatalf("a refused close-out changed the footprint from %d to %d", used, after)
		}
		if _, err := scanStreamReadOnly(dir); err != nil {
			t.Fatalf("the refused close-out left the stream unreplayable: %v", err)
		}

		// The refusal has to be an answer an operator can act on, not a dead
		// end: the documented remedy is raising the cap, after which the very
		// same stream closes out unchanged and inside the new bound.
		raised := int64(budget) * 2
		retry := installCloseOutProbe(t, dir, 0)
		if err := appendRecoveryReleaseCertificate(dir, scan, scan.lastSeq, digest, scopes, raised); err != nil {
			t.Fatalf("raising the cap to %d must let the same close-out through: %v", raised, err)
		}
		retry.observe()
		if retry.peak > raised {
			t.Fatalf("close-out peaked at %d bytes, past the raised %d-byte budget", retry.peak, raised)
		}
	})

	t.Run("marker fits, releases do not: the reclaim path still completes", func(t *testing.T) {
		const budget = 256 << 10
		dir, scan, digest, scopes := reclaimablyLegacyStream(t, budget)

		used := streamFootprint(t, dir)
		appliedBytes, releaseBytes := closeOutCost(t, scan, digest, scopes)
		if used+appliedBytes+releaseBytes <= budget {
			t.Fatalf("fixture takes the fast path (%d+%d+%d <= %d); the reclaim path is untested",
				used, appliedBytes, releaseBytes, budget)
		}
		if used+appliedBytes > budget {
			t.Fatalf("fixture's marker peak %d does not fit %d; this case is meant to succeed",
				used+appliedBytes, budget)
		}
		if segs := streamSegmentCount(t, dir); segs < 2 {
			t.Fatalf("fixture has nothing to reclaim (%d segments)", segs)
		}

		probe := installCloseOutProbe(t, dir, 0)
		err := appendRecoveryReleaseCertificate(dir, scan, scan.lastSeq, digest, scopes, budget)
		probe.observe()

		if err != nil {
			t.Fatalf("a close-out whose peak and final footprint both fit must succeed: %v", err)
		}
		if probe.peak > budget {
			t.Fatalf("close-out peaked at %d bytes, past the %d-byte budget", probe.peak, budget)
		}
		if after := streamFootprint(t, dir); after > budget {
			t.Fatalf("close-out settled at %d bytes, past the %d-byte budget", after, budget)
		}
		if segs := streamSegmentCount(t, dir); segs != 1 {
			t.Fatalf("the close-out did not reclaim the applied prefix (%d segments left)", segs)
		}
		// The reclaim is only legitimate if the retained tail can still rebuild
		// the digest — that is what barrier A is written for.
		reduced, err := scanStreamReadOnly(dir)
		if err != nil {
			t.Fatalf("the reclaimed stream no longer replays: %v", err)
		}
		live, _, marks, _, err := decodeStreamFrames(reduced.frames)
		if err != nil {
			t.Fatalf("decode reclaimed stream: %v", err)
		}
		if len(live) != 0 {
			t.Fatalf("the close-out left %d scopes live: %v", len(live), live)
		}
		got, err := digestAt(reduced, marks, reduced.lastSeq)
		if err != nil {
			t.Fatalf("the reclaimed stream cannot rebuild the digest at its tail: %v", err)
		}
		if got != digest {
			t.Fatalf("the reclaimed stream rebuilt digest %x at its tail, want %x", got, digest)
		}
	})
}

// TestLegacyCloseOutRefusesBeforeAppendingWhenPeakCannotFit pins the "decided
// before the first byte" half of the contract. A gate that refuses only after
// barrier A is already durable has not refused anything: the overshoot happened,
// and on a full store the stream is left with a mark it cannot pay for. The
// refusal must be arithmetic, and the stream must come out byte-identical.
func TestLegacyCloseOutRefusesBeforeAppendingWhenPeakCannotFit(t *testing.T) {
	const budget = 256 << 10
	dir, scan, digest, scopes := atCapLegacyStream(t, budget)

	used := streamFootprint(t, dir)
	appliedBytes, _ := closeOutCost(t, scan, digest, scopes)
	if used+appliedBytes <= budget {
		t.Fatalf("fixture is not at the cap: peak %d fits the %d-byte budget", used+appliedBytes, budget)
	}
	before := streamBytes(t, dir)
	appliedBefore := countAppliedFrames(t, dir)

	probe := installCloseOutProbe(t, dir, 0)
	err := appendRecoveryReleaseCertificate(dir, scan, scan.lastSeq, digest, scopes, budget)

	if !errors.Is(err, errCloseOutUnbounded) {
		t.Fatalf("want the definite typed close-out answer, got %v", err)
	}
	if !strings.Contains(err.Error(), "transient peak") {
		t.Fatalf("the refusal must name the bound it could not meet, got %q", err)
	}
	if probe.calls != 0 {
		t.Fatalf("a refused close-out performed %d appends; the decision must precede every write", probe.calls)
	}
	if after := streamBytes(t, dir); !equalStreamBytes(before, after) {
		t.Fatalf("a refused close-out changed the stream on disk (%s)", describeStreamDiff(before, after))
	}
	if got := countAppliedFrames(t, dir); got != appliedBefore {
		t.Fatalf("a refused close-out left %d APPLIED frames, want the original %d", got, appliedBefore)
	}
}

func equalStreamBytes(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, body := range a {
		if b[name] != body {
			return false
		}
	}
	return true
}

func describeStreamDiff(before, after map[string]string) string {
	var parts []string
	for name, body := range before {
		other, ok := after[name]
		switch {
		case !ok:
			parts = append(parts, fmt.Sprintf("%s removed", name))
		case other != body:
			parts = append(parts, fmt.Sprintf("%s %d -> %d bytes", name, len(body), len(other)))
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			parts = append(parts, fmt.Sprintf("%s added", name))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// TestLegacyCloseOutENOSPCAtMarkerBarrierIsDefinite covers the failure the
// arithmetic gate cannot see. BudgetBytes bounds this stream's share of the
// device; it says nothing about the device being full for other reasons. If a
// close-out append returns ENOSPC, no number of attach retries will make space
// appear, yet the caller's only special case is errCloseOutUnbounded — everything
// else is wrapped in errRetryable and retried on every attach forever, leaving
// the delegation grant checked out to a stream that can never resolve.
//
// A physical out-of-space is the same fact as an arithmetic overrun ("this
// close-out does not fit"), so it must produce the same DEFINITE typed answer an
// operator can act on, at every append the close-out performs.
func TestLegacyCloseOutENOSPCAtMarkerBarrierIsDefinite(t *testing.T) {
	const budget = 256 << 10
	for _, tc := range []struct {
		name   string
		build  func(*testing.T, int64) (string, *streamScan, [32]byte, []RebindScope)
		budget int64
		failAt int
	}{
		{"barrier A, the marker append", reclaimablyLegacyStream, budget, 1},
		{"barrier C, the release append", reclaimablyLegacyStream, budget, 2},
		{"the fast path's single append", atCapLegacyStream, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The fast-path case is built against a real cap and then run with
			// the budget disabled, so it takes the unreclaimed route.
			dir, scan, digest, scopes := tc.build(t, budget)
			probe := installCloseOutProbe(t, dir, tc.failAt)
			err := appendRecoveryReleaseCertificate(dir, scan, scan.lastSeq, digest, scopes, tc.budget)

			if probe.calls < tc.failAt {
				t.Fatalf("the close-out never reached append %d (%d performed)", tc.failAt, probe.calls)
			}
			if !errors.Is(err, errCloseOutUnbounded) {
				t.Fatalf("an ENOSPC close-out append must be the definite typed answer, got %v", err)
			}
			if errors.Is(err, errRetryable) {
				t.Fatalf("an ENOSPC close-out append must never be retryable, got %v", err)
			}
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("the underlying ENOSPC must stay visible, got %v", err)
			}
			if !strings.Contains(err.Error(), syscall.ENOSPC.Error()) {
				t.Fatalf("the message must name the physical cause, got %q", err)
			}
		})
	}
}

// TestLegacyCloseOutENOSPCParksTheJobAsADefiniteConflict asserts the same fact
// where it is actually observable to an operator: recoverStream's own handling.
// The tail is already applied at the authority by this point, so a retryable
// classification would fail every attach forever while the grants stay checked
// out. The job must park in the typed CLOSE_OUT_UNBOUNDED conflict the mount
// surfaces once, exactly as an arithmetic refusal does.
func TestLegacyCloseOutENOSPCParksTheJobAsADefiniteConflict(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	mountID, err := ensureMountID(stateDir)
	if err != nil {
		t.Fatalf("mount identity: %v", err)
	}
	s := newLegacyStream(t, stateDir, mountID, "vol", "main", 1)
	s.delegation("d", "epoch-d")
	s.mutation(wal.Record{Op: wal.OpCreate, Path: "d/f", Mode: 0o644})
	s.mutation(wal.Record{Op: wal.OpWrite, Path: "d/f", Data: []byte("legacy tail")})
	s.finish()

	dir := filepath.Join(stateDir, streamDirName(1))
	auth := newFakeAuthority()
	seedLegacyGrants(auth, streamID(mountID, 1), map[string]string{"d": "epoch-d"})

	// A budget with room to spare: the only thing that can fail the close-out is
	// the device underneath it.
	probe := installCloseOutProbe(t, dir, 1)
	e, err := Open(ctx, Config{
		StateDir: stateDir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("an out-of-space close-out must be surfaced, not fail the attach: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()
	if probe.calls != 1 {
		t.Fatalf("the close-out performed %d appends, want exactly the injected one", probe.calls)
	}

	jobs := e.Status().Jobs
	if len(jobs) != 1 {
		t.Fatalf("want exactly one surfaced recovery job, got %+v", jobs)
	}
	if jobs[0].State != JobConflict {
		t.Fatalf("want a typed terminal conflict, got state %q (%s)", jobs[0].State, jobs[0].LastError)
	}
	if len(jobs[0].Conflicts) != 1 || jobs[0].Conflicts[0].Kind != "CLOSE_OUT_UNBOUNDED" {
		t.Fatalf("want a CLOSE_OUT_UNBOUNDED conflict detail, got %+v", jobs[0].Conflicts)
	}
	if !strings.Contains(jobs[0].LastError, syscall.ENOSPC.Error()) {
		t.Fatalf("the surfaced error must name the physical cause, got %q", jobs[0].LastError)
	}
}
