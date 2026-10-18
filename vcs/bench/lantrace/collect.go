package lantrace

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// DefaultMaxEvents is the default bound on events in one collection.
	DefaultMaxEvents = 4 << 20
	// DefaultMaxBytes is the default bound on event bytes in one collection.
	DefaultMaxBytes = 1 << 30
	// MaxDistinctLabels bounds the distinct mount, session and superblock labels of one run. Labels name a handful of
	// run-local objects; a run that needs more is using them as per-file or
	// per-request identities, which the content rule forbids, so further new
	// labels are rejected.
	MaxDistinctLabels = 256
)

// CollectConfig bounds a collection. Zero fields take the defaults.
type CollectConfig struct {
	// MaxEvents bounds the events written; later events are dropped.
	MaxEvents int64
	// MaxBytes bounds the bytes of event lines written; later events are
	// dropped. The collection, header, trailer and summary lines are not
	// charged: they are at most (2*streams + 2) short lines.
	MaxBytes int64
}

// Input is one producer stream. Name appears only in error messages.
type Input struct {
	Name   string
	Reader io.Reader
}

// Summary is the collection's accounting, also written as its last record.
type Summary struct {
	Run               Label  `json:"run"`
	Streams           int    `json:"streams"`
	Events            uint64 `json:"events"`
	Dropped           uint64 `json:"dropped"`
	Rejected          uint64 `json:"rejected"`
	ProducerLost      uint64 `json:"producer_lost"`
	IncompleteStreams uint64 `json:"incomplete_streams"`
	// InconsistentStreams counts complete streams whose sequence numbers do
	// not reconcile with their trailer under the sequence rule.
	InconsistentStreams uint64 `json:"inconsistent_streams"`
}

type inputStream struct {
	index    uint32
	name     string
	lines    *lineReader
	header   Header
	pending  *record
	base     Nanos
	baseSet  bool
	lastSeq  uint64
	trailer  *record
	read     uint64
	rejected uint64
	done     bool
}

// Collect validates the producer streams of one run and writes one collection
// document to w:
//
//	{"record":"collection","schema":...,"run":R,"streams":N}
//	N headers, each with "stream":i (1-based, in input order)
//	events, each with "stream":i
//	N trailers: {"record":"trailer","stream":i,"emitted":E,"lost":X,"read":R,"rejected":J[,"incomplete":true][,"inconsistent":true]}
//	{"record":"summary","events":W,"dropped":D,"rejected":J,"producer_lost":X,"incomplete_streams":I,"inconsistent_streams":C}
//
// Every input must begin with a valid header and all must name the same run;
// otherwise Collect fails before writing. A later invalid line is rejected
// and counted, and an input without its trailer is recorded as incomplete.
// A complete input whose sequence numbers do not reconcile with its trailer
// under the sequence rule is recorded as inconsistent.
// Collect holds one pending event per input and a bounded label set, so its
// memory does not grow with input size.
//
// Events are interleaved by each stream's own elapsed time since its first
// event. That order only keeps correlated records near each other for the
// report's bounded join window; it is never used to compute an interval,
// because different streams' clocks are not comparable.
func Collect(w io.Writer, inputs []Input, cfg CollectConfig) (Summary, error) {
	var sum Summary
	if len(inputs) == 0 || len(inputs) > MaxStreams {
		return sum, fmt.Errorf("lantrace: collect needs 1 to %d inputs", MaxStreams)
	}
	if cfg.MaxEvents < 0 || cfg.MaxBytes < 0 {
		return sum, errors.New("lantrace: collect bounds must not be negative")
	}
	if cfg.MaxEvents == 0 {
		cfg.MaxEvents = DefaultMaxEvents
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}

	streams := make([]*inputStream, len(inputs))
	for i, in := range inputs {
		s := &inputStream{index: uint32(i + 1), name: in.Name, lines: newLineReader(in.Reader)}
		line, err := s.lines.next()
		if err != nil {
			return sum, fmt.Errorf("lantrace: input %s: missing header: %w", in.Name, err)
		}
		rec, err := parseLine(line, false)
		if err != nil {
			return sum, fmt.Errorf("lantrace: input %s: invalid header: %w", in.Name, err)
		}
		if rec.Record != recordHeader {
			return sum, fmt.Errorf("lantrace: input %s: first record is not a header", in.Name)
		}
		s.header = rec.header()
		if i > 0 && s.header.Run != streams[0].header.Run {
			return sum, fmt.Errorf("lantrace: input %s names a different run than input %s", in.Name, streams[0].name)
		}
		streams[i] = s
	}
	sum.Run, sum.Streams = streams[0].header.Run, len(streams)

	bw := bufio.NewWriterSize(w, 64<<10)
	writeFixed := func(b []byte) error {
		if _, err := bw.Write(b); err != nil {
			return fmt.Errorf("lantrace: write collection: %w", err)
		}
		return nil
	}
	if err := writeFixed(marshalLine(struct {
		Record  string `json:"record"`
		Schema  string `json:"schema"`
		Run     Label  `json:"run"`
		Streams int    `json:"streams"`
	}{recordCollection, Schema, sum.Run, sum.Streams})); err != nil {
		return sum, err
	}
	for _, s := range streams {
		if err := writeFixed(encodeHeader(s.index, s.header)); err != nil {
			return sum, err
		}
	}

	labels := map[Label]struct{}{}
	for _, s := range streams {
		if err := s.advance(labels); err != nil {
			return sum, err
		}
	}
	var bytesWritten int64
	var buf []byte
	for {
		var next *inputStream
		for _, s := range streams {
			if s.pending != nil && (next == nil || s.elapsed() < next.elapsed()) {
				next = s
			}
		}
		if next == nil {
			break
		}
		ev := next.pending
		body, err := json.Marshal(&ev.Event)
		if err != nil {
			return sum, fmt.Errorf("lantrace: encode event: %w", err)
		}
		buf = appendEvent(buf[:0], next.index, ev.Seq, ev.T, body)
		if int64(sum.Events) < cfg.MaxEvents && bytesWritten+int64(len(buf)) <= cfg.MaxBytes {
			if err := writeFixed(buf); err != nil {
				return sum, err
			}
			sum.Events++
			bytesWritten += int64(len(buf))
		} else {
			sum.Dropped++
		}
		if err := next.advance(labels); err != nil {
			return sum, err
		}
	}

	for _, s := range streams {
		t := struct {
			Record       string `json:"record"`
			Stream       uint32 `json:"stream"`
			Emitted      uint64 `json:"emitted"`
			Lost         uint64 `json:"lost"`
			Read         uint64 `json:"read"`
			Rejected     uint64 `json:"rejected"`
			Incomplete   bool   `json:"incomplete,omitempty"`
			Inconsistent bool   `json:"inconsistent,omitempty"`
		}{Record: recordTrailer, Stream: s.index, Read: s.read, Rejected: s.rejected}
		if s.trailer != nil {
			t.Emitted, t.Lost = s.trailer.Emitted, s.trailer.Lost
			sum.ProducerLost += s.trailer.Lost
			if !sequenceConsistent(s.lastSeq, s.read, s.rejected, t.Emitted, t.Lost) {
				t.Inconsistent = true
				sum.InconsistentStreams++
			}
		} else {
			t.Incomplete = true
			sum.IncompleteStreams++
		}
		sum.Rejected += s.rejected
		if err := writeFixed(marshalLine(t)); err != nil {
			return sum, err
		}
	}
	if err := writeFixed(marshalLine(struct {
		Record              string `json:"record"`
		Events              uint64 `json:"events"`
		Dropped             uint64 `json:"dropped"`
		Rejected            uint64 `json:"rejected"`
		ProducerLost        uint64 `json:"producer_lost"`
		IncompleteStreams   uint64 `json:"incomplete_streams"`
		InconsistentStreams uint64 `json:"inconsistent_streams"`
	}{recordSummary, sum.Events, sum.Dropped, sum.Rejected, sum.ProducerLost, sum.IncompleteStreams, sum.InconsistentStreams})); err != nil {
		return sum, err
	}
	if err := bw.Flush(); err != nil {
		return sum, fmt.Errorf("lantrace: write collection: %w", err)
	}
	return sum, nil
}

// sequenceConsistent applies the stream sequence rule (see the package
// documentation) to one complete stream: every accepted event consumed the
// next number, written or lost, so the last written number cannot exceed
// emitted+lost, at most emitted events can have been read, and with nothing
// rejected exactly emitted must have been read. Written numbers are already
// strictly increasing, so together these mean every gap is a counted loss and
// no loss is counted twice. A rejected line may have been an event, so with
// rejections only the bounds can be checked; the rejection itself already
// invalidates attribution.
func sequenceConsistent(lastSeq, read, rejected, emitted, lost uint64) bool {
	if read > emitted || lastSeq > satAdd(emitted, lost) {
		return false
	}
	return rejected > 0 || read == emitted
}

func (s *inputStream) elapsed() Nanos {
	if s.pending.T < s.base {
		return 0
	}
	return s.pending.T - s.base
}

// advance reads until the next valid event, the end of the input, or a read
// error. Invalid records are counted, never echoed.
func (s *inputStream) advance(labels map[Label]struct{}) error {
	s.pending = nil
	for !s.done {
		line, err := s.lines.next()
		if err == io.EOF {
			s.done = true
			break
		}
		if err == errLineTooLong {
			s.rejected++
			continue
		}
		if err != nil {
			return fmt.Errorf("lantrace: input %s: %w", s.name, err)
		}
		rec, err := parseLine(line, false)
		if err != nil || s.trailer != nil {
			s.rejected++
			continue
		}
		switch rec.Record {
		case recordTrailer:
			s.trailer = &rec
			continue
		case recordEvent:
		default:
			s.rejected++
			continue
		}
		if rec.checkEvent(s.header.Layer) != nil || rec.Seq <= s.lastSeq || !admitLabels(labels, &rec.Event) {
			s.rejected++
			continue
		}
		s.lastSeq = rec.Seq
		if !s.baseSet {
			s.base, s.baseSet = rec.T, true
		}
		s.read++
		s.pending = &rec
		return nil
	}
	return nil
}

// admitLabels records the event's labels, refusing (and rolling back) an
// event that would introduce a new label beyond MaxDistinctLabels.
func admitLabels(labels map[Label]struct{}, e *Event) bool {
	var added []Label
	for _, l := range [...]Label{e.Mount, e.Session, e.Superblock} {
		if l == "" {
			continue
		}
		if _, ok := labels[l]; ok {
			continue
		}
		if len(labels) >= MaxDistinctLabels {
			for _, a := range added {
				delete(labels, a)
			}
			return false
		}
		labels[l] = struct{}{}
		added = append(added, l)
	}
	return true
}
