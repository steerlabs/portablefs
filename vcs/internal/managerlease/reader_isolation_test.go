package managerlease

import (
	"context"
	"encoding/json"
	"io"
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
}

func (p *slowProber) ProbeLeaseFacts(ctx context.Context) (LeaseFacts, error) {
	p.calls.Add(1)
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
	prober := &slowProber{latency: probeLatency}
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
	if got := prober.maxFlgt.Load(); got > 1 {
		t.Fatalf("%d probes were in flight at once; grounding must stay single-flight", got)
	}
	if got := prober.calls.Load(); got < 1 {
		t.Fatal("no grounding ran at all")
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
	guard.SetProber(&slowProber{latency: 150 * time.Millisecond})

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
