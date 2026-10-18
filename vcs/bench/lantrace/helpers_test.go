package lantrace

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const testRun Label = "run-test"

// testConnNS is the shared connection namespace both sides of the test
// frontend/daemon joins carry.
const testConnNS Label = "cns-test"

// streamBuilder writes a producer stream line by line so tests control every
// record, including invalid ones.
type streamBuilder struct {
	buf    bytes.Buffer
	seq    uint64
	events uint64
}

func newStream(layer Layer) *streamBuilder {
	return newStreamFor(testRun, layer)
}

func newStreamFor(run Label, layer Layer) *streamBuilder {
	s := &streamBuilder{}
	s.buf.Write(encodeHeader(0, Header{Run: run, Layer: layer, Process: Label("proc-" + strings.ReplaceAll(string(layer), "_", "-")), Clock: "test-clock"}))
	return s
}

func (s *streamBuilder) ev(t Nanos, e Event) *streamBuilder {
	s.seq++
	return s.evSeq(s.seq, t, e)
}

func (s *streamBuilder) evSeq(seq uint64, t Nanos, e Event) *streamBuilder {
	body, err := json.Marshal(&e)
	if err != nil {
		panic(err)
	}
	s.buf.Write(appendEvent(nil, 0, seq, t, body))
	s.events++
	return s
}

func (s *streamBuilder) raw(line string) *streamBuilder {
	s.buf.WriteString(line + "\n")
	return s
}

// end writes a trailer that claims every ev call as emitted.
func (s *streamBuilder) end(lost uint64) *streamBuilder {
	s.buf.Write(encodeProducerTrailer(s.events, lost))
	return s
}

func (s *streamBuilder) input(name string) Input {
	return Input{Name: name, Reader: bytes.NewReader(s.buf.Bytes())}
}

func collectStreams(t *testing.T, cfg CollectConfig, streams ...*streamBuilder) ([]byte, Summary) {
	t.Helper()
	inputs := make([]Input, len(streams))
	for i, s := range streams {
		inputs[i] = s.input(string(rune('a' + i)))
	}
	var out bytes.Buffer
	sum, err := Collect(&out, inputs, cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return out.Bytes(), sum
}

func reportOf(t *testing.T, collection []byte, cfg ReportConfig) *Report {
	t.Helper()
	rep, err := BuildReport(bytes.NewReader(collection), cfg)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	return rep
}

func frontendSend(conn, request uint64, op LocalOp) Event {
	return Event{Kind: KindLocal, Phase: PhaseSend, ConnNS: testConnNS, Conn: conn, Request: request, LocalOp: op}
}

func daemonEnqueue(conn, request uint64, op LocalOp) Event {
	return Event{Kind: KindLocal, Phase: PhaseEnqueue, ConnNS: testConnNS, Conn: conn, Request: request, LocalOp: op}
}

// inNamespace returns e with its connection namespace replaced; an empty
// namespace models a producer that cannot prove the shared identity.
func inNamespace(ns Label, e Event) Event {
	e.ConnNS = ns
	return e
}

func authoritySend(session Label, id uint64, op AuthorityOp) Event {
	return Event{Kind: KindAuthority, Phase: PhaseSend, Session: session, AuthorityRequest: id, AuthorityOp: op, Dispatch: DispatchOriginal}
}

func authorityReceive(session Label, id uint64, op AuthorityOp) Event {
	return Event{Kind: KindAuthority, Phase: PhaseReceive, Session: session, AuthorityRequest: id, AuthorityOp: op}
}

func waitEvent(d Nanos) Event {
	return Event{Kind: KindWait, Wait: WaitReservation, Duration: d}
}
