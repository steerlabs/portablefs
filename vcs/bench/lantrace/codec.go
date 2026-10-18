package lantrace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Record type names.
const (
	recordHeader     = "header"
	recordEvent      = "event"
	recordTrailer    = "trailer"
	recordCollection = "collection"
	recordSummary    = "summary"
)

// Header identifies one producer stream.
type Header struct {
	Run     Label `json:"run"`
	Layer   Layer `json:"layer"`
	Process Label `json:"process"`
	Clock   Label `json:"clock"`
}

func (h Header) validate() error {
	switch {
	case !h.Run.valid():
		return errors.New("lantrace: header run is not a valid label")
	case !h.Layer.valid():
		return errors.New("lantrace: header layer is not a known layer")
	case !h.Process.valid():
		return errors.New("lantrace: header process is not a valid label")
	case !h.Clock.valid():
		return errors.New("lantrace: header clock is not a valid label")
	}
	return nil
}

// record is the union of every line shape. Which keys a line may carry is
// decided by allowedKeys before decoding, so the union never admits a key in
// the wrong record.
type record struct {
	Record string `json:"record"`
	Stream uint32 `json:"stream"`
	Seq    uint64 `json:"seq"`
	T      Nanos  `json:"t_ns"`

	Schema  string `json:"schema"`
	Run     Label  `json:"run"`
	Layer   Layer  `json:"layer"`
	Process Label  `json:"process"`
	Clock   Label  `json:"clock"`
	Streams uint32 `json:"streams"`

	Emitted    uint64 `json:"emitted"`
	Lost       uint64 `json:"lost"`
	Read       uint64 `json:"read"`
	Rejected   uint64 `json:"rejected"`
	Incomplete bool   `json:"incomplete"`

	Events            uint64 `json:"events"`
	Dropped           uint64 `json:"dropped"`
	ProducerLost      uint64 `json:"producer_lost"`
	IncompleteStreams uint64 `json:"incomplete_streams"`

	Event

	eventKeys fieldSet
}

func (r *record) header() Header {
	return Header{Run: r.Run, Layer: r.Layer, Process: r.Process, Clock: r.Clock}
}

// checkEvent validates the embedded event for a stream of layer. Presence is
// defined by non-zero values, so a key the line carried with a zero value is
// a non-canonical encoding and rejected.
func (r *record) checkEvent(layer Layer) error {
	present, err := r.Event.validate(layer)
	if err != nil {
		return err
	}
	if present != r.eventKeys {
		return fmt.Errorf("lantrace: field %q carries an explicit zero value", firstKey(r.eventKeys&^present))
	}
	if r.Seq == 0 {
		return errors.New("lantrace: event seq must be positive")
	}
	if !r.T.valid() {
		return errors.New("lantrace: event t_ns exceeds the bound")
	}
	return nil
}

type keyRule struct {
	allowed  map[string]bool
	required map[string]bool
}

func newKeyRule(required, optional []string) keyRule {
	r := keyRule{allowed: map[string]bool{}, required: map[string]bool{}}
	for _, k := range required {
		r.allowed[k], r.required[k] = true, true
	}
	for _, k := range optional {
		r.allowed[k] = true
	}
	return r
}

var (
	headerKeys = []string{"record", "schema", "run", "layer", "process", "clock"}
	eventKeys  = []string{"record", "seq", "t_ns"}

	producerRules = map[string]keyRule{
		recordHeader:  newKeyRule(headerKeys, nil),
		recordEvent:   newKeyRule(eventKeys, nil),
		recordTrailer: newKeyRule([]string{"record", "emitted", "lost"}, nil),
	}
	collectionRules = map[string]keyRule{
		recordCollection: newKeyRule([]string{"record", "schema", "run", "streams"}, nil),
		recordHeader:     newKeyRule(append([]string{"stream"}, headerKeys...), nil),
		recordEvent:      newKeyRule(append([]string{"stream"}, eventKeys...), nil),
		recordTrailer:    newKeyRule([]string{"record", "stream", "emitted", "lost", "read", "rejected"}, []string{"incomplete"}),
		recordSummary:    newKeyRule([]string{"record", "events", "dropped", "rejected", "producer_lost", "incomplete_streams"}, nil),
	}
)

// parseLine decodes one line under the producer or collection grammar. It
// enforces the structural rules (one flat object, exact allowlisted keys, no
// duplicates, scalar values, nothing after the object) and the header and
// envelope bounds; event field validation needs the stream's layer and is
// left to checkEvent.
func parseLine(line []byte, collection bool) (record, error) {
	var rec record
	keys, kind, err := scanObject(line)
	if err != nil {
		return rec, err
	}
	rulesFor := producerRules
	if collection {
		rulesFor = collectionRules
	}
	kr, ok := rulesFor[kind]
	if !ok {
		return rec, errors.New("lantrace: unknown or missing record type")
	}
	for _, k := range keys {
		if kr.allowed[k] {
			continue
		}
		f, isEvent := eventFieldByKey[k]
		if kind != recordEvent || !isEvent {
			return rec, fmt.Errorf("lantrace: %s record has an unknown key", kind)
		}
		rec.eventKeys |= f.bit
	}
	for k := range kr.required {
		if !containsKey(keys, k) {
			return rec, fmt.Errorf("lantrace: %s record is missing key %q", kind, k)
		}
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return rec, fmt.Errorf("lantrace: %s record has a value of the wrong type", kind)
	}
	if collection && kind != recordCollection && kind != recordSummary && rec.Stream == 0 {
		return rec, errors.New("lantrace: stream index must be positive")
	}
	switch kind {
	case recordHeader:
		if rec.Schema != Schema {
			return rec, errors.New("lantrace: unsupported schema")
		}
		if err := rec.header().validate(); err != nil {
			return rec, err
		}
	case recordCollection:
		if rec.Schema != Schema {
			return rec, errors.New("lantrace: unsupported schema")
		}
		if !rec.Run.valid() {
			return rec, errors.New("lantrace: collection run is not a valid label")
		}
		if rec.Streams == 0 || rec.Streams > MaxStreams {
			return rec, fmt.Errorf("lantrace: collection must declare 1 to %d streams", MaxStreams)
		}
	}
	return rec, nil
}

func containsKey(keys []string, k string) bool {
	for _, key := range keys {
		if key == k {
			return true
		}
	}
	return false
}

// scanObject walks one JSON object token by token. Decoding straight into a
// struct would silently accept duplicate keys, case-folded key matches and
// nested values; this pass rejects all of them first. Errors never quote a
// key or value from the line.
func scanObject(line []byte) (keys []string, recordType string, err error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, "", errors.New("lantrace: line is not a JSON object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, "", errors.New("lantrace: malformed JSON")
		}
		key, _ := tok.(string)
		if containsKey(keys, key) {
			return nil, "", errors.New("lantrace: duplicate key")
		}
		keys = append(keys, key)
		val, err := dec.Token()
		if err != nil {
			return nil, "", errors.New("lantrace: malformed JSON")
		}
		switch v := val.(type) {
		case string:
			if key == "record" {
				recordType = v
			}
		case json.Number, bool:
		default:
			return nil, "", errors.New("lantrace: values must be strings, numbers or booleans")
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, "", errors.New("lantrace: malformed JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, "", errors.New("lantrace: data after the JSON object")
	}
	return keys, recordType, nil
}

var errLineTooLong = fmt.Errorf("lantrace: line exceeds %d bytes", MaxLineBytes)

// lineReader yields lines of at most MaxLineBytes. An oversized line is
// consumed and reported as errLineTooLong without ever being buffered whole,
// so hostile input cannot grow memory.
type lineReader struct{ br *bufio.Reader }

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, MaxLineBytes)}
}

// next returns the line without its newline, io.EOF at the end, or
// errLineTooLong. A final line without a newline is still returned.
func (l *lineReader) next() ([]byte, error) {
	line, err := l.br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		for err == bufio.ErrBufferFull {
			_, err = l.br.ReadSlice('\n')
		}
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("lantrace: read: %w", err)
		}
		return nil, errLineTooLong
	}
	if err == io.EOF {
		if len(line) == 0 {
			return nil, io.EOF
		}
		return line, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lantrace: read: %w", err)
	}
	return line[:len(line)-1], nil
}

// appendEvent encodes an event record. body is the JSON encoding of a
// validated Event, so it is an object that starts with its kind key.
func appendEvent(dst []byte, stream uint32, seq uint64, t Nanos, body []byte) []byte {
	dst = append(dst, `{"record":"event",`...)
	if stream > 0 {
		dst = append(dst, `"stream":`...)
		dst = strconv.AppendUint(dst, uint64(stream), 10)
		dst = append(dst, ',')
	}
	dst = append(dst, `"seq":`...)
	dst = strconv.AppendUint(dst, seq, 10)
	dst = append(dst, `,"t_ns":`...)
	dst = strconv.AppendUint(dst, uint64(t), 10)
	dst = append(dst, ',')
	dst = append(dst, body[1:]...)
	return append(dst, '\n')
}

func encodeHeader(stream uint32, h Header) []byte {
	return marshalLine(struct {
		Record  string `json:"record"`
		Stream  uint32 `json:"stream,omitempty"`
		Schema  string `json:"schema"`
		Run     Label  `json:"run"`
		Layer   Layer  `json:"layer"`
		Process Label  `json:"process"`
		Clock   Label  `json:"clock"`
	}{recordHeader, stream, Schema, h.Run, h.Layer, h.Process, h.Clock})
}

func encodeProducerTrailer(emitted, lost uint64) []byte {
	return marshalLine(struct {
		Record  string `json:"record"`
		Emitted uint64 `json:"emitted"`
		Lost    uint64 `json:"lost"`
	}{recordTrailer, emitted, lost})
}

func marshalLine(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Every caller passes a fixed struct of strings and integers.
		panic("lantrace: marshal fixed record: " + err.Error())
	}
	return append(b, '\n')
}
