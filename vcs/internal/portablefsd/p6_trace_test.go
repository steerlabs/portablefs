package portablefsd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func p6Recorder(t *testing.T, w io.Writer, layer lantrace.Layer, cfg lantrace.RecorderConfig) *lantrace.Recorder {
	t.Helper()
	r, err := lantrace.NewRecorder(w, "p6-test", layer, lantrace.Label("process-"+string(layer)), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func p6TraceReport(t *testing.T, streams ...[]byte) *lantrace.Report {
	t.Helper()
	inputs := make([]lantrace.Input, len(streams))
	for i, stream := range streams {
		inputs[i] = lantrace.Input{Name: "test", Reader: bytes.NewReader(stream)}
	}
	var collection bytes.Buffer
	if _, err := lantrace.Collect(&collection, inputs, lantrace.CollectConfig{}); err != nil {
		t.Fatal(err)
	}
	report, err := lantrace.BuildReport(&collection, lantrace.ReportConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func p6TraceEvents(t *testing.T, stream []byte) []lantrace.Event {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(stream))
	var events []lantrace.Event
	for {
		var rec struct {
			Record string `json:"record"`
			lantrace.Event
		}
		if err := dec.Decode(&rec); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if rec.Record == "event" {
			events = append(events, rec.Event)
		}
	}
	return events
}

func TestP6TraceCollectorReceivesTwoWireConnections(t *testing.T) {
	var stream bytes.Buffer
	r := p6Recorder(t, &stream, lantrace.LayerDaemon, lantrace.RecorderConfig{})
	// The helper exercises actual enqueue, handler, disposition, ack,
	// reservation/cleanup and terminal paths, with repeated IDs on two sockets.
	t.Run("wire", func(t *testing.T) { p6WireSaturation(t, r) })
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	var frontend bytes.Buffer
	fr := p6Recorder(t, &frontend, lantrace.LayerFrontend, lantrace.RecorderConfig{})
	for _, e := range p6TraceEvents(t, stream.Bytes()) {
		if e.Kind == lantrace.KindLocal && e.Phase == lantrace.PhaseEnqueue {
			e.Phase = lantrace.PhaseSend
			e.Conn = lantrace.TraceID("frontend-" + string(e.Conn))
			if err := fr.Emit(e); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := fr.Close(); err != nil {
		t.Fatal(err)
	}
	report := p6TraceReport(t, frontend.Bytes(), stream.Bytes())
	if report.Events == 0 || report.Rejected != 0 || report.ProducerLost != 0 || report.IncompleteStreams != 0 || report.InconsistentStreams != 0 {
		t.Fatalf("producer failed shared collection: %+v", report)
	}
	conns := map[lantrace.TraceID]bool{}
	phases := map[lantrace.Phase]bool{}
	unbound := 0
	for _, e := range p6TraceEvents(t, stream.Bytes()) {
		if e.RequestID == 0 {
			continue
		}
		if e.Kind != lantrace.KindLocal || e.FrontendPID != uint32(os.Getpid()) || e.Conn == "" || e.ConnRole == "" || e.LocalOp == "" {
			t.Fatalf("incomplete request identity: %+v", e)
		}
		conns[e.Conn] = true
		phases[e.Phase] = true
		if e.LocalOp == lantrace.LocalHello {
			if e.AttachRef != "" {
				t.Fatalf("Hello fabricated attach: %+v", e)
			}
			unbound++
		} else if e.AttachRef != testFSKitAttachRef {
			t.Fatalf("wrong exact Resolve identity: %+v", e)
		}
	}
	if len(conns) != 2 || unbound != 4 || !phases[lantrace.PhaseOutcome] || !phases[lantrace.PhaseReply] || !phases[lantrace.PhaseDisposition] {
		t.Fatalf("missing connections, pre-bind or non-anchor records: conns=%v unbound=%d phases=%v", conns, unbound, phases)
	}
	// Full handshake traces deliberately contain pre-bind evidence. The actual
	// reporter must retain it and refuse exact attribution, not discard it.
	if report.AttributionValid || report.Joins[0].Status != lantrace.JoinUnavailable {
		t.Fatalf("pre-bind evidence hidden: %+v", report.Joins)
	}
}

func TestP6TraceBoundConnectionsJoinAndNonAnchorAmbiguityInvalidates(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "non-anchor-ambiguity"}[ambiguous], func(t *testing.T) {
			var daemon, frontend bytes.Buffer
			dr := p6Recorder(t, &daemon, lantrace.LayerDaemon, lantrace.RecorderConfig{})
			fr := p6Recorder(t, &frontend, lantrace.LayerFrontend, lantrace.RecorderConfig{})
			for i, role := range []string{"p6.one", "p6.two"} {
				c := &frontendConn{srv: NewServer(Config{Trace: dr}), frontendPID: os.Getpid(), origin: uint64(i + 41),
					helloClientName: role, attach: &attach{ref: testFSKitAttachRef}}
				trace := c.requestTrace(3, 7, &pfslocal.LookupRequest{})
				trace.local(lantrace.PhaseEnqueue, 0)
				trace.local(lantrace.PhaseDispatch, 0)
				trace.local(lantrace.PhaseOutcome, 0)
				trace.local(lantrace.PhaseReply, 0)
				trace.local(lantrace.PhaseDisposition, 0)
				if err := fr.Emit(lantrace.Event{Kind: lantrace.KindLocal, Phase: lantrace.PhaseSend, LocalOp: lantrace.LocalLookup,
					FrontendPID: uint32(os.Getpid()), AttachRef: testFSKitAttachRef, ConnRole: lantrace.TraceID(role), Conn: lantrace.TraceID("frontend-" + role), RequestID: 3, Operation: 7}); err != nil {
					t.Fatal(err)
				}
				if ambiguous && i == 0 {
					other := &frontendConn{srv: c.srv, frontendPID: c.frontendPID, origin: 99, helloClientName: role, attach: c.attach}
					other.requestTrace(4, 8, &pfslocal.LookupRequest{}).local(lantrace.PhaseOutcome, 0)
				}
			}
			if err := dr.Close(); err != nil {
				t.Fatal(err)
			}
			if err := fr.Close(); err != nil {
				t.Fatal(err)
			}
			report := p6TraceReport(t, frontend.Bytes(), daemon.Bytes())
			if report.Rejected != 0 || report.ProducerLost != 0 {
				t.Fatalf("invalid producer: %+v", report)
			}
			join := report.Joins[0]
			if !ambiguous && (!report.AttributionValid || join.Status != lantrace.JoinExact || join.Matched != 2) {
				t.Fatalf("exact bound identities failed: %+v", report)
			}
			if ambiguous && (report.AttributionValid || join.Status != lantrace.JoinUnavailable || join.Matched != 0) {
				t.Fatalf("non-anchor ambiguity hidden: %+v", report)
			}
		})
	}
}

type p6BlockedTraceSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	bytes.Buffer
}

func (w *p6BlockedTraceSink) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.Buffer.Write(b)
}

func TestReviewP6TraceDoesNotWaitForSink(t *testing.T) {
	w := &p6BlockedTraceSink{entered: make(chan struct{}), release: make(chan struct{})}
	r := p6Recorder(t, w, lantrace.LayerDaemon, lantrace.RecorderConfig{QueueEvents: 2})
	var once sync.Once
	unblock := func() { once.Do(func() { close(w.release) }) }
	defer func() { unblock(); _ = r.Close() }()
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("trace writer never reached sink")
	}
	// No sink byte can complete until after the complete production progress
	// proof: queued-reader cancellation, dispositions, both acks, release
	// acceptance, socket close, cleanup and a terminal transition.
	t.Run("blocked", func(t *testing.T) { p6WireSaturation(t, r) })
	if r.Lost() == 0 {
		t.Fatal("bounded queue did not account for overflow")
	}
	unblock()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	report := p6TraceReport(t, w.Bytes())
	if report.AttributionValid || report.ProducerLost != r.Lost() || report.InconsistentStreams != 0 || report.Rejected != 0 {
		t.Fatalf("lost trace claimed exact attribution or broke sequence accounting: %+v", report)
	}
}

func TestP6TraceInvalidIdentityCountsLoss(t *testing.T) {
	var stream bytes.Buffer
	r := p6Recorder(t, &stream, lantrace.LayerDaemon, lantrace.RecorderConfig{})
	c := &frontendConn{srv: NewServer(Config{Trace: r}), frontendPID: os.Getpid(), origin: 77,
		helloClientName: "exact role outside alphabet", attach: &attach{ref: testFSKitAttachRef}}
	c.requestTrace(3, 7, &pfslocal.LookupRequest{}).local(lantrace.PhaseOutcome, 0)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	report := p6TraceReport(t, stream.Bytes())
	if report.AttributionValid || report.ProducerLost != 1 || report.Events != 0 || report.Rejected != 0 || report.InconsistentStreams != 0 {
		t.Fatalf("invalid exact identity was normalized or silently discarded: %+v", report)
	}
}
