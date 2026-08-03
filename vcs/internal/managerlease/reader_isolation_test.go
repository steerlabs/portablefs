package managerlease

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowProber stands in for the capability-bound lease-facts read while the
// database is busy: every probe takes `latency`. It answers correctly — the
// child is healthy, the binding is current — it is merely not instantaneous.
type slowProber struct {
	latency time.Duration
	calls   atomic.Int64
	inFlgt  atomic.Int64
	maxFlgt atomic.Int64
	// entered is closed when the FIRST probe is ENTERED (before its latency is
	// paid). Grounding runs on its own goroutine by design — that is the whole
	// point of this file — so "a probe was issued" is an event a test must
	// WAIT for, never one it may assume has already happened.
	enteredOnce sync.Once
	entered     chan struct{}
}

func newSlowProber(latency time.Duration) *slowProber {
	return &slowProber{latency: latency, entered: make(chan struct{})}
}

func (p *slowProber) ProbeLeaseFacts(ctx context.Context) (LeaseFacts, error) {
	p.calls.Add(1)
	p.enteredOnce.Do(func() { close(p.entered) })
	if n := p.inFlgt.Add(1); n > p.maxFlgt.Load() {
		p.maxFlgt.Store(n)
	}
	defer p.inFlgt.Add(-1)
	select {
	case <-time.After(p.latency):
	case <-ctx.Done():
		return LeaseFacts{}, ctx.Err()
	}
	now := time.Now().UnixMilli()
	return LeaseFacts{
		Current: true, DBTimeMs: now, ExpiresAtDbMs: now + 60_000,
		ManagerEpoch: "7", AuthorityRuntimeSeq: "3", AuthorityRuntimeID: "pfrt_a",
	}, nil
}

func frameLine(t *testing.T, seq int64) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"v": FrameVersion, "seq": seq,
		"managerEpoch": "7", "managerRuntimeId": "pfmr_a",
		"authorityInstanceId": "pfai_a", "authorityRuntimeSeq": "3",
		"authorityRuntimeId": "pfrt_a",
		"dbTimeMs":           1_000_000, "leaseRemainingMs": 60_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

// countingReader feeds pre-rendered frames and records how many the guard has
// actually consumed, so a stalled reader is directly observable.
type countingReader struct {
	frames [][]byte
	idx    int
	off    int
	read   atomic.Int64
	drain  chan struct{}
	park   chan struct{}
	closed bool
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.frames) {
		// Every frame consumed: block instead of EOF (EOF fences by design).
		if !r.closed {
			r.closed = true
			close(r.drain)
		}
		// Park instead of returning EOF: EOF fences by design, and this test
		// is about what happens while the pipe is healthy.
		<-r.park
	}
	frame := r.frames[r.idx]
	n := copy(p, frame[r.off:])
	r.off += n
	if r.off == len(frame) {
		r.idx++
		r.off = 0
		r.read.Add(1)
	}
	return n, nil
}

// TestSlowProbeNeverStallsTheLeasePipeReader is the reader half of the
// load-coupling root fix.
//
// The manager writes lease frames into an inherited pipe and treats a pipe the
// child stops draining as a dead child. Grounding used to run INLINE in the
// reader loop, so the child's ability to drain that pipe was gated on database
// latency — exactly the resource that saturating apply traffic exhausts. A
// healthy child doing useful work therefore looked, from the pipe, identical
// to a hung one.
//
// With grounding handed to its own goroutine the reader drains at pipe speed
// regardless of probe latency: all frames are consumed promptly, and at most
// one probe is ever in flight.
func TestSlowProbeNeverStallsTheLeasePipeReader(t *testing.T) {
	const frames = 12
	const probeLatency = 300 * time.Millisecond

	guard := NewGuard(Identity{
		ManagerEpoch: "7", ManagerRuntimeID: "pfmr_a", AuthorityInstanceID: "pfai_a",
		AuthorityRuntimeSeq: "3", AuthorityRuntimeID: "pfrt_a",
	}, 100*time.Millisecond)
	prober := newSlowProber(probeLatency)
	guard.SetProber(prober)

	reader := &countingReader{drain: make(chan struct{}), park: make(chan struct{})}
	for seq := int64(1); seq <= frames; seq++ {
		reader.frames = append(reader.frames, frameLine(t, seq))
	}

	go guard.Run(reader)

	// Inline grounding would need frames*probeLatency (3.6s) to drain the
	// pipe; a decoupled reader needs only pipe time.
	select {
	case <-reader.drain:
	case <-time.After(frames * probeLatency / 2):
		t.Fatalf("lease pipe reader stalled behind the database probe: drained %d/%d frames",
			reader.read.Load(), frames)
	case <-guard.Fenced():
		t.Fatalf("a healthy child fenced while the database was slow: %v", guard.Cause())
	}

	if got := reader.read.Load(); got != frames {
		t.Fatalf("consumed %d frames, want %d", got, frames)
	}
	select {
	case <-guard.Fenced():
		t.Fatalf("guard fenced a healthy child: %v", guard.Cause())
	default:
	}
	// WAIT for the first grounding rather than assuming it beat the drain.
	//
	// The two events are concurrent by construction and have no ordering
	// between them: the reader consumes 12 in-memory frames without ever
	// reaching a scheduling point, so by the time `drain` closes, the
	// `go groundLoop()` that the first frame spawned has had essentially no
	// opportunity to run. Whether it did depends entirely on whether some
	// other P stole it in that window — this test used to pass on that luck.
	// Proof it was luck: at aad03e9, with none of the round-21c changes
	// present, GOMAXPROCS=1 fails this assertion 30 out of 30 runs and
	// GOMAXPROCS=2 passes 30 out of 30.
	//
	// The bound is generous on purpose but still catches the regression that
	// matters — grounding not starting at all — because the first probe is
	// issued exactly when the child has NO armed deadline to fall back on.
	// Measured on this package over 900 iterations of that unarmed path:
	// p50 25 us, p99 ~130 us, max 396 us, never-started 0. Two seconds is
	// over 5000x the observed maximum.
	select {
	case <-prober.entered:
	case <-guard.Fenced():
		t.Fatalf("guard fenced a healthy child before grounding: %v", guard.Cause())
	case <-time.After(2 * time.Second):
		t.Fatal("no grounding ran at all")
	}

	// Checked only once a probe is known to have started, so single-flight is
	// asserted against real evidence instead of an empty counter.
	if got := prober.maxFlgt.Load(); got > 1 {
		t.Fatalf("%d probes were in flight at once; grounding must stay single-flight", got)
	}
}

// A slow probe must still keep the deadline alive: latest-value coalescing
// drops redundant TRIGGERS, never the grounding itself, so serving is still
// authorized and the guard never fences while the database keeps answering.
func TestSlowProbeStillGroundsAndAuthorizesServing(t *testing.T) {
	guard := NewGuard(Identity{
		ManagerEpoch: "7", ManagerRuntimeID: "pfmr_a", AuthorityInstanceID: "pfai_a",
		AuthorityRuntimeSeq: "3", AuthorityRuntimeID: "pfrt_a",
	}, 100*time.Millisecond)
	guard.SetProber(newSlowProber(150 * time.Millisecond))

	reader := &countingReader{drain: make(chan struct{}), park: make(chan struct{})}
	for seq := int64(1); seq <= 5; seq++ {
		reader.frames = append(reader.frames, frameLine(t, seq))
	}
	go guard.Run(reader)

	select {
	case <-guard.FirstFrame():
	case <-guard.Fenced():
		t.Fatalf("fenced before grounding: %v", guard.Cause())
	case <-time.After(5 * time.Second):
		t.Fatal("a slow but healthy probe never authorized serving")
	}
}

var _ io.Reader = (*countingReader)(nil)
