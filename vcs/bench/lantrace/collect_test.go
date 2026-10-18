package lantrace

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestCollectRefusesInvalidInputs(t *testing.T) {
	good := func() *streamBuilder { return newStream(LayerDaemon).ev(1, waitEvent(1)).end(0) }
	cases := []struct {
		name   string
		inputs []Input
		want   string
	}{
		{"no inputs", nil, "1 to 64 inputs"},
		{"empty input", []Input{{Name: "empty", Reader: strings.NewReader("")}}, "missing header"},
		{"event first", []Input{{Name: "headless", Reader: strings.NewReader(
			`{"record":"event","seq":1,"t_ns":0,"kind":"wait","wait":"transport","dur_ns":1}` + "\n")}}, "first record is not a header"},
		{"bad header", []Input{{Name: "old", Reader: strings.NewReader(
			`{"record":"header","schema":"pfs-lan-trace-0","run":"r","layer":"daemon","process":"p","clock":"c"}` + "\n")}}, "invalid header"},
		{"oversized header", []Input{{Name: "huge", Reader: strings.NewReader(strings.Repeat("x", 2*MaxLineBytes) + "\n")}}, "missing header"},
		{"mixed run", []Input{good().input("a"), newStreamFor("other-run", LayerAuthority).end(0).input("b")}, "different run"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := Collect(&out, tc.inputs, CollectConfig{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Collect error = %v, want %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Fatalf("refused collection wrote %d bytes", out.Len())
			}
		})
	}
}

func TestCollectCountsRejectedRecordsAndIncompleteStreams(t *testing.T) {
	front := newStream(LayerFrontend).
		ev(10, frontendSend(1, 1, LocalLookup)).
		raw(`{"record":"event","seq":2,"t_ns":11,"kind":"local","phase":"send","conn":1,"request":2,"local_op":"lookup","path":"/x"}`).
		raw(strings.Repeat("y", MaxLineBytes+10)).
		raw(`{"record":"header","schema":"pfs-lan-trace-1","run":"run-test","layer":"frontend","process":"p","clock":"c"}`).
		evSeq(3, 12, frontendSend(1, 3, LocalLookup)).
		evSeq(3, 13, frontendSend(1, 4, LocalLookup)). // repeated seq
		evSeq(5, 14, Event{Kind: KindCache, Phase: PhaseFinal, Conn: 1, Request: 3, Candidate: CandidateEntryCache, CacheResult: CacheMiss}).
		end(0).
		raw(`{"record":"trailer","emitted":2,"lost":0}`)
	// Two valid events read, but the trailer claims all four ev calls.
	daemon := newStream(LayerDaemon).
		ev(5, daemonEnqueue(1, 1, LocalLookup)).
		ev(6, daemonEnqueue(1, 3, LocalLookup)) // no trailer
	out, sum := collectStreams(t, CollectConfig{}, front, daemon)
	want := Summary{Run: testRun, Streams: 2, Events: 4, Rejected: 6, IncompleteStreams: 1}
	if sum != want {
		t.Fatalf("summary = %+v, want %+v", sum, want)
	}
	rep := reportOf(t, out, ReportConfig{})
	if rep.AttributionValid {
		t.Fatal("collection with rejected records and an incomplete stream reported exact attribution")
	}
	if s := rep.Streams[0]; s.Read != 2 || s.Rejected != 6 || s.Emitted != 4 || s.Incomplete {
		t.Fatalf("frontend stream = %+v", s)
	}
	if s := rep.Streams[1]; s.Read != 2 || !s.Incomplete {
		t.Fatalf("daemon stream = %+v", s)
	}
	reasons := strings.Join(rep.InvalidReasons, "\n")
	for _, want := range []string{"6 records rejected", "1 streams have no trailer", "stream 1 trailer reports 4 events but 2 were read"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("reasons %q lack %q", reasons, want)
		}
	}
	if bytes.Contains(out, []byte("/x")) {
		t.Fatal("rejected content reached the collection")
	}
}

func TestCollectBounds(t *testing.T) {
	stream := func() *streamBuilder {
		s := newStream(LayerDaemon)
		for i := range 10 {
			s.ev(Nanos(i), waitEvent(1))
		}
		return s.end(0)
	}
	oneLine := int64(len(appendEvent(nil, 1, 1, 0, []byte(`{"kind":"wait","wait":"reservation","dur_ns":1}`))))
	cases := []struct {
		name            string
		cfg             CollectConfig
		events, dropped uint64
	}{
		{"defaults", CollectConfig{}, 10, 0},
		{"max events", CollectConfig{MaxEvents: 3}, 3, 7},
		{"max bytes", CollectConfig{MaxBytes: 2*oneLine + 1}, 2, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, sum := collectStreams(t, tc.cfg, stream())
			if sum.Events != tc.events || sum.Dropped != tc.dropped {
				t.Fatalf("summary = %+v", sum)
			}
			rep := reportOf(t, out, ReportConfig{})
			if rep.Counters["daemon.wait.reservation"] != tc.events {
				t.Fatalf("report saw %d waits", rep.Counters["daemon.wait.reservation"])
			}
			if rep.AttributionValid != (tc.dropped == 0) {
				t.Fatalf("attribution valid = %t with %d dropped", rep.AttributionValid, tc.dropped)
			}
		})
	}
	if _, err := Collect(&bytes.Buffer{}, []Input{stream().input("a")}, CollectConfig{MaxEvents: -1}); err == nil {
		t.Fatal("negative bound accepted")
	}
}

// Events are interleaved by each stream's own elapsed time, never by raw
// timestamps from unrelated clocks.
// The sequence rule: every gap in a stream's written numbers is a counted
// loss, and nothing is read beyond what the trailer says was emitted.
func TestCollectReconcilesSequenceWithTrailer(t *testing.T) {
	cases := []struct {
		name         string
		stream       *streamBuilder
		inconsistent uint64
	}{
		{"dense", newStream(LayerDaemon).ev(0, waitEvent(1)).ev(1, waitEvent(2)).end(0), 0},
		{"gap explained by loss", newStream(LayerDaemon).evSeq(1, 0, waitEvent(1)).evSeq(3, 1, waitEvent(2)).end(1), 0},
		{"tail loss beyond the last written number", newStream(LayerDaemon).ev(0, waitEvent(1)).end(3), 0},
		{"gap without a counted loss", newStream(LayerDaemon).evSeq(1, 0, waitEvent(1)).evSeq(3, 1, waitEvent(2)).end(0), 1},
		{"more events than emitted", newStream(LayerDaemon).ev(0, waitEvent(1)).ev(1, waitEvent(2)).raw(`{"record":"trailer","emitted":1,"lost":1}`), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, sum := collectStreams(t, CollectConfig{}, tc.stream)
			if sum.InconsistentStreams != tc.inconsistent {
				t.Fatalf("inconsistent streams = %d, want %d (%+v)", sum.InconsistentStreams, tc.inconsistent, sum)
			}
			rep := reportOf(t, out, ReportConfig{})
			if rep.InconsistentStreams != tc.inconsistent {
				t.Fatalf("report inconsistent streams = %d, want %d", rep.InconsistentStreams, tc.inconsistent)
			}
			if tc.inconsistent > 0 && rep.AttributionValid {
				t.Fatal("an inconsistent stream certified exact attribution")
			}
		})
	}
}

func TestCollectInterleavesByPerStreamElapsedTime(t *testing.T) {
	a := newStream(LayerDaemon).ev(1000, waitEvent(1)).ev(1010, waitEvent(2)).ev(1020, waitEvent(3)).end(0)
	b := newStream(LayerAuthority).ev(5, waitEvent(4)).ev(15, waitEvent(5)).end(0)
	out, _ := collectStreams(t, CollectConfig{}, a, b)
	var order []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, `"record":"event"`) {
			continue
		}
		rec, err := parseLine([]byte(line), true)
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, fmt.Sprintf("%d:%d", rec.Stream, rec.Duration))
	}
	if got, want := strings.Join(order, " "), "1:1 2:4 1:2 2:5 1:3"; got != want {
		t.Fatalf("order %q, want %q", got, want)
	}
}

func TestCollectBoundsDistinctLabels(t *testing.T) {
	s := newStream(LayerDaemon)
	for i := range MaxDistinctLabels + 5 {
		e := waitEvent(1)
		e.Session = Label(fmt.Sprintf("s%d", i))
		s.ev(Nanos(i), e)
	}
	// Reusing an admitted label is always allowed.
	e := waitEvent(1)
	e.Session = "s0"
	s.ev(1000, e)
	_, sum := collectStreams(t, CollectConfig{}, s.end(0))
	if sum.Events != MaxDistinctLabels+1 || sum.Rejected != 5 {
		t.Fatalf("summary = %+v", sum)
	}
}
