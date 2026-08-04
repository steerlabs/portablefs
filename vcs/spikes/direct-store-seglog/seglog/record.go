// Package seglog implements a segmented append-only mutation/value log with a
// rebuildable index over log offsets. It is a measurement spike, not a
// production storage engine: it exists so that physical write amplification,
// durability latency, read latency, recovery time, and steady-state segment
// cleaning cost can be measured against real kernel counters.
package seglog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Record layout. Every record is self-describing and checksummed so that a
// forward scan can find the last structurally valid record without any
// external metadata.
//
//	 0..3   magic
//	 4..7   CRC-32C over bytes 8..end
//	 8..15  sequence number
//	16      kind
//	17      reserved
//	18..19  key length
//	20..23  value length
//	24..    key, then value
const (
	recordMagic  = 0x47534650 // "PFSG" little-endian
	HeaderBytes  = 24
	MaxKeyBytes  = 1 << 16
	MaxValueSize = 1 << 26
)

// Record kinds.
const (
	KindPut     uint8 = 1
	KindDelete  uint8 = 2
	KindTrailer uint8 = 3 // group-commit boundary; value holds the record count
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// ErrCorrupt reports a record that cannot be trusted. A forward scan treats it
// as the end of the readable log rather than as a fatal condition.
var ErrCorrupt = errors.New("seglog: record is not structurally valid")

// EncodeRecord returns one framed record.
func EncodeRecord(seq uint64, kind uint8, key, value []byte) ([]byte, error) {
	if len(key) > MaxKeyBytes {
		return nil, fmt.Errorf("seglog: key is %d bytes", len(key))
	}
	if len(value) > MaxValueSize {
		return nil, fmt.Errorf("seglog: value is %d bytes", len(value))
	}
	out := make([]byte, HeaderBytes+len(key)+len(value))
	binary.LittleEndian.PutUint32(out[0:], recordMagic)
	binary.LittleEndian.PutUint64(out[8:], seq)
	out[16] = kind
	binary.LittleEndian.PutUint16(out[18:], uint16(len(key)))
	binary.LittleEndian.PutUint32(out[20:], uint32(len(value)))
	copy(out[HeaderBytes:], key)
	copy(out[HeaderBytes+len(key):], value)
	binary.LittleEndian.PutUint32(out[4:], crc32.Checksum(out[8:], castagnoli))
	return out, nil
}

// Header is the decoded fixed-size prefix of a record.
type Header struct {
	Seq      uint64
	Kind     uint8
	KeyLen   int
	ValueLen int
}

// Total is the on-disk size of the whole record.
func (h Header) Total() int64 { return int64(HeaderBytes + h.KeyLen + h.ValueLen) }

// DecodeHeader validates the magic and returns the framing fields. It does not
// verify the checksum, which needs the full record body.
func DecodeHeader(buf []byte) (Header, error) {
	if len(buf) < HeaderBytes {
		return Header{}, ErrCorrupt
	}
	if binary.LittleEndian.Uint32(buf[0:]) != recordMagic {
		return Header{}, ErrCorrupt
	}
	h := Header{
		Seq:      binary.LittleEndian.Uint64(buf[8:]),
		Kind:     buf[16],
		KeyLen:   int(binary.LittleEndian.Uint16(buf[18:])),
		ValueLen: int(binary.LittleEndian.Uint32(buf[20:])),
	}
	if h.Kind != KindPut && h.Kind != KindDelete && h.Kind != KindTrailer {
		return Header{}, ErrCorrupt
	}
	if h.ValueLen > MaxValueSize {
		return Header{}, ErrCorrupt
	}
	return h, nil
}

// DecodeRecord validates one complete record and returns its key and value as
// subslices of buf.
func DecodeRecord(buf []byte) (Header, []byte, []byte, error) {
	h, err := DecodeHeader(buf)
	if err != nil {
		return Header{}, nil, nil, err
	}
	total := h.Total()
	if int64(len(buf)) < total {
		return Header{}, nil, nil, ErrCorrupt
	}
	if crc32.Checksum(buf[8:total], castagnoli) != binary.LittleEndian.Uint32(buf[4:]) {
		return Header{}, nil, nil, ErrCorrupt
	}
	key := buf[HeaderBytes : HeaderBytes+h.KeyLen]
	value := buf[HeaderBytes+h.KeyLen : total]
	return h, key, value, nil
}
