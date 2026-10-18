package lantrace

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var daemonHeader = Header{Run: testRun, Layer: LayerDaemon, Process: "portablefsd", Clock: GoMonotonicClock}

func zeroClock() Nanos { return 0 }

// blockingWriter blocks every Write until released, recording that the first
// Write has started so tests can fill the queue deterministically.
type blockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	buf     bytes.Buffer
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// parsedStream validates a producer stream and returns its events and trailer.
func parsedStream(t *testing.T, data []byte) (events []record, trailer record) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("stream has %d lines", len(lines))
	}
	head, err := parseLine([]byte(lines[0]), false)
	if err != nil || head.Record != recordHeader {
		t.Fatalf("bad header %q: %v", lines[0], err)
	}
	var lastSeq uint64
	for _, l := range lines[1 : len(lines)-1] {
		rec, err := parseLine([]byte(l), false)
		if err != nil || rec.Record != recordEvent {
			t.Fatalf("bad event %q: %v", l, err)
		}
		if err := rec.checkEvent(head.Layer); err != nil {
			t.Fatalf("invalid event %q: %v", l, err)
		}
		if rec.Seq <= lastSeq {
			t.Fatalf("seq %d after %d", rec.Seq, lastSeq)
		}
		lastSeq = rec.Seq
		events = append(events, rec)
	}
	trailer, err = parseLine([]byte(lines[len(lines)-1]), false)
	if err != nil || trailer.Record != recordTrailer {
		t.Fatalf("bad trailer %q: %v", lines[len(lines)-1], err)
	}
	return events, trailer
}

func TestRecorderWritesHeaderEventsAndTrailer(t *testing.T) {
	var buf bytes.Buffer
	r, err := NewRecorder(&buf, testRun, LayerDaemon, "portablefsd", RecorderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if err := r.Emit(waitEvent(Nanos(i + 1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	events, trailer := parsedStream(t, buf.Bytes())
	if len(events) != 10 || trailer.Emitted != 10 || trailer.Lost != 0 {
		t.Fatalf("events=%d trailer=%+v", len(events), trailer)
	}
	var lastT Nanos
	for i, e := range events {
		if e.Duration != Nanos(i+1) || e.T < lastT {
			t.Fatalf("event %d: %+v", i, e)
		}
		lastT = e.T
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := r.Emit(waitEvent(1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Emit after Close = %v", err)
	}
}

// A sink that never drains must cost the producer nothing but lost events.
func TestRecorderOverflowCountsLostWithoutBlocking(t *testing.T) {
	w := newBlockingWriter()
	r, err := newRecorder(w, daemonHeader, RecorderConfig{QueueEvents: 4}, zeroClock)
	if err != nil {
		t.Fatal(err)
	}
	<-w.entered // the drain goroutine is now stuck flushing the header
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			if err := r.Emit(waitEvent(1)); err != nil {
				t.Error(err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Emit blocked on a stalled sink")
	}
	if got := r.Lost(); got != 16 {
		t.Fatalf("Lost() = %d with a full 4-event queue, want 16", got)
	}
	close(w.release)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	events, trailer := parsedStream(t, w.buf.Bytes())
	if len(events) != 4 || trailer.Emitted != 4 || trailer.Lost != 16 {
		t.Fatalf("events=%d trailer=%+v", len(events), trailer)
	}
	// Dropped events consumed seq numbers, so the gap is visible.
	if events[3].Seq != 4 {
		t.Fatalf("queued events carry seq %d..%d", events[0].Seq, events[3].Seq)
	}
}

func TestRecorderByteBudgetCountsLost(t *testing.T) {
	body := `"kind":"wait","wait":"reservation","dur_ns":1}`
	lineLen := int64(len(`{"record":"event","seq":1,"t_ns":0,`) + len(body) + 1)
	cases := []struct {
		name          string
		budget        int64
		emitted, lost uint64
	}{
		{"exact fit for three", 3 * lineLen, 3, 6},
		{"one byte short of three", 3*lineLen - 1, 2, 7},
		{"smaller than one event", lineLen - 1, 0, 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			r, err := newRecorder(&buf, daemonHeader, RecorderConfig{ByteBudget: tc.budget}, zeroClock)
			if err != nil {
				t.Fatal(err)
			}
			for range 9 {
				if err := r.Emit(waitEvent(1)); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			events, trailer := parsedStream(t, buf.Bytes())
			if uint64(len(events)) != tc.emitted || trailer.Emitted != tc.emitted || trailer.Lost != tc.lost {
				t.Fatalf("events=%d trailer=%+v, want emitted=%d lost=%d", len(events), trailer, tc.emitted, tc.lost)
			}
		})
	}
}

func TestRecorderRejectsInvalidEventsAndCountsThemLost(t *testing.T) {
	cases := []struct {
		name string
		e    Event
	}{
		{"wrong layer", Event{Kind: KindCallback, Phase: PhaseEntry, Callback: 1, CallbackKind: CallbackLookup}},
		{"free text label", Event{Kind: KindWait, Wait: WaitTransport, Duration: 1, Session: "session /tmp/x"}},
		{"missing duration", Event{Kind: KindWait, Wait: WaitTransport}},
		{"no kind", Event{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			r, err := newRecorder(&buf, daemonHeader, RecorderConfig{}, zeroClock)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Emit(tc.e); err == nil {
				t.Fatal("invalid event accepted")
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			events, trailer := parsedStream(t, buf.Bytes())
			if len(events) != 0 || trailer.Emitted != 0 || trailer.Lost != 1 {
				t.Fatalf("events=%d trailer=%+v", len(events), trailer)
			}
		})
	}
}

func TestRecorderRejectsInvalidConfiguration(t *testing.T) {
	cases := []struct {
		name string
		h    Header
		cfg  RecorderConfig
	}{
		{"bad run", Header{Run: "a run", Layer: LayerDaemon, Process: "p", Clock: "c"}, RecorderConfig{}},
		{"bad layer", Header{Run: "r", Layer: "kernel", Process: "p", Clock: "c"}, RecorderConfig{}},
		{"negative queue", daemonHeader, RecorderConfig{QueueEvents: -1}},
		{"negative budget", daemonHeader, RecorderConfig{ByteBudget: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newRecorder(&bytes.Buffer{}, tc.h, tc.cfg, zeroClock); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRecorderConcurrentEmitKeepsOrderAndCounts(t *testing.T) {
	var buf bytes.Buffer
	r, err := NewRecorder(&buf, testRun, LayerDaemon, "portablefsd", RecorderConfig{QueueEvents: 1 << 13})
	if err != nil {
		t.Fatal(err)
	}
	const workers, each = 8, 500
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				e := Event{Kind: KindLocal, Phase: PhaseEnqueue, Conn: uint64(w + 1), Request: uint64(i + 1), LocalOp: LocalLookup}
				if err := r.Emit(e); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	events, trailer := parsedStream(t, buf.Bytes())
	if got := uint64(len(events)) + trailer.Lost; got != workers*each || trailer.Emitted != uint64(len(events)) {
		t.Fatalf("events=%d trailer=%+v", len(events), trailer)
	}
	var lastT Nanos
	for _, e := range events {
		if e.T < lastT {
			t.Fatalf("t_ns went backwards at seq %d", e.Seq)
		}
		lastT = e.T
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRecorderReportsSinkFailure(t *testing.T) {
	boom := errors.New("disk gone")
	r, err := newRecorder(failingWriter{boom}, daemonHeader, RecorderConfig{}, zeroClock)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := r.Emit(waitEvent(1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close = %v, want the sink error", err)
	}
}

func ExampleRecorder() {
	var trace bytes.Buffer
	r, err := NewRecorder(&trace, "probe-32", LayerAuthority, "authority", RecorderConfig{})
	if err != nil {
		panic(err)
	}
	_ = r.Emit(Event{Kind: KindSyscall, Syscall: SyscallSyncfs, Duration: 1500, Waiters: 3, Superblock: "sb1"})
	if err := r.Close(); err != nil {
		panic(err)
	}
	lines := strings.Split(strings.TrimSpace(trace.String()), "\n")
	fmt.Println(lines[0])
	fmt.Println(lines[2])
	// Output:
	// {"record":"header","schema":"pfs-lan-trace-1","run":"probe-32","layer":"authority","process":"authority","clock":"go-monotonic"}
	// {"record":"trailer","emitted":1,"lost":0}
}
