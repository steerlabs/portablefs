package directstoreharness

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
)

const traceVersion = uint16(1)

var traceMagic = [8]byte{'P', 'F', 'S', 'F', 'L', 'T', '0', '1'}

type Digest [sha256.Size]byte

func (d Digest) String() string { return hex.EncodeToString(d[:]) }

func digestBytes(data []byte) Digest { return sha256.Sum256(data) }

type EventKind uint8

const (
	EventFaultArmed EventKind = iota + 1
	EventCutBefore
	EventDiskWrite
	EventDiskSync
	EventCutAfter
	EventCrash
	EventRestart
	EventMessageDeliver
	EventMessageDrop
	EventMessageDuplicate
	EventCommit
	EventApply
	EventReply
	EventRead
	EventViolation
)

type TraceEvent struct {
	Operation uint64
	Kind      EventKind
	Node      NodeID
	Peer      NodeID
	Index     uint64
	Point     string
	Detail    string
	Digest    Digest
}

type TraceHeader struct {
	Seed       uint64
	Operations uint64
	Catalog    Digest
	Mode       string
}

// Recorder writes a compact, length-delimited binary trace and hashes the
// exact same bytes. A nil output retains only the hash for soak runs; failures
// can then be rerun from the seed with an output writer without changing the
// schedule.
type Recorder struct {
	output *bufio.Writer
	hash   hash.Hash
	step   uint64
	err    error
	buf    []byte
	frame  []byte
}

func NewRecorder(output io.Writer, header TraceHeader) *Recorder {
	r := &Recorder{hash: sha256.New(), buf: make([]byte, 0, 256), frame: make([]byte, 0, 272)}
	if output != nil {
		r.output = bufio.NewWriterSize(output, 256*1024)
	}
	r.writeHeader(header)
	return r
}

func (r *Recorder) writeHeader(header TraceHeader) {
	buf := r.buf[:0]
	buf = append(buf, traceMagic[:]...)
	buf = binary.LittleEndian.AppendUint16(buf, traceVersion)
	buf = binary.LittleEndian.AppendUint64(buf, header.Seed)
	buf = binary.LittleEndian.AppendUint64(buf, header.Operations)
	buf = append(buf, header.Catalog[:]...)
	buf = appendString(buf, header.Mode)
	r.write(buf)
}

func (r *Recorder) Emit(event TraceEvent) {
	if r.err != nil {
		return
	}
	r.step++
	buf := r.buf[:0]
	buf = binary.AppendUvarint(buf, r.step)
	buf = binary.AppendUvarint(buf, event.Operation)
	buf = append(buf, byte(event.Kind), byte(event.Node), byte(event.Peer))
	buf = binary.AppendUvarint(buf, event.Index)
	buf = appendString(buf, event.Point)
	buf = appendString(buf, event.Detail)
	buf = append(buf, event.Digest[:]...)
	frame := r.frame[:0]
	frame = binary.AppendUvarint(frame, uint64(len(buf)))
	frame = append(frame, buf...)
	r.write(frame)
}

func appendString(dst []byte, value string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(value)))
	return append(dst, value...)
}

func (r *Recorder) write(data []byte) {
	if r.err != nil {
		return
	}
	if _, err := r.hash.Write(data); err != nil {
		r.err = err
		return
	}
	if r.output != nil {
		_, r.err = r.output.Write(data)
	}
}

func (r *Recorder) Finish() (Digest, error) {
	if r.output != nil && r.err == nil {
		r.err = r.output.Flush()
	}
	var digest Digest
	copy(digest[:], r.hash.Sum(nil))
	return digest, r.err
}

func (r *Recorder) Events() uint64 { return r.step }

// DecodeTrace exists for diagnostics and tests; replay uses the seed rather
// than trusting a possibly truncated trace as an instruction stream.
func DecodeTrace(input io.Reader) (TraceHeader, []TraceEvent, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return TraceHeader{}, nil, err
	}
	if len(data) < len(traceMagic)+2+8+8+sha256.Size || !bytes.Equal(data[:len(traceMagic)], traceMagic[:]) {
		return TraceHeader{}, nil, fmt.Errorf("invalid direct-store fault trace header")
	}
	offset := len(traceMagic)
	version := binary.LittleEndian.Uint16(data[offset:])
	offset += 2
	if version != traceVersion {
		return TraceHeader{}, nil, fmt.Errorf("unsupported direct-store fault trace version %d", version)
	}
	header := TraceHeader{
		Seed:       binary.LittleEndian.Uint64(data[offset:]),
		Operations: binary.LittleEndian.Uint64(data[offset+8:]),
	}
	offset += 16
	copy(header.Catalog[:], data[offset:offset+sha256.Size])
	offset += sha256.Size
	header.Mode, offset, err = readString(data, offset)
	if err != nil {
		return TraceHeader{}, nil, err
	}
	var events []TraceEvent
	for offset < len(data) {
		length, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return TraceHeader{}, nil, fmt.Errorf("invalid event frame at byte %d", offset)
		}
		offset += n
		if length > uint64(len(data)-offset) {
			return TraceHeader{}, nil, io.ErrUnexpectedEOF
		}
		frameEnd := offset + int(length)
		_, n = binary.Uvarint(data[offset:]) // step is diagnostic only
		if n <= 0 {
			return TraceHeader{}, nil, fmt.Errorf("invalid event step at byte %d", offset)
		}
		offset += n
		operation, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return TraceHeader{}, nil, fmt.Errorf("invalid event operation at byte %d", offset)
		}
		offset += n
		if len(data)-offset < 3 {
			return TraceHeader{}, nil, io.ErrUnexpectedEOF
		}
		event := TraceEvent{Operation: operation, Kind: EventKind(data[offset]), Node: NodeID(data[offset+1]), Peer: NodeID(data[offset+2])}
		offset += 3
		event.Index, n = binary.Uvarint(data[offset:])
		if n <= 0 {
			return TraceHeader{}, nil, fmt.Errorf("invalid event index at byte %d", offset)
		}
		offset += n
		event.Point, offset, err = readString(data, offset)
		if err != nil {
			return TraceHeader{}, nil, err
		}
		event.Detail, offset, err = readString(data, offset)
		if err != nil {
			return TraceHeader{}, nil, err
		}
		if len(data)-offset < sha256.Size {
			return TraceHeader{}, nil, io.ErrUnexpectedEOF
		}
		copy(event.Digest[:], data[offset:offset+sha256.Size])
		offset += sha256.Size
		if offset != frameEnd {
			return TraceHeader{}, nil, fmt.Errorf("event frame ended at byte %d, decoded to %d", frameEnd, offset)
		}
		events = append(events, event)
	}
	return header, events, nil
}

func readString(data []byte, offset int) (string, int, error) {
	length, n := binary.Uvarint(data[offset:])
	if n <= 0 {
		return "", offset, fmt.Errorf("invalid trace string at byte %d", offset)
	}
	offset += n
	if length > uint64(len(data)-offset) {
		return "", offset, io.ErrUnexpectedEOF
	}
	return string(data[offset : offset+int(length)]), offset + int(length), nil
}
