// Package pfwire implements the strict deterministic wire primitives shared by
// the frozen PortableFS canonical codecs (PFR1 for wal.Record, PFC1 for ctlrec
// payloads). The encoding is protowire-shaped (field numbers + wire types,
// varints, length-delimited bytes) but deliberately stricter than protobuf:
// there is EXACTLY ONE valid byte representation for any value.
//
// Canonical rules enforced by this package:
//
//   - Fields are emitted in strictly ascending field-number order. A decoder
//     rejects any field whose number is not greater than the previous field's
//     (which also rejects duplicate singular fields). Repeated fields are
//     emitted as consecutive records for the SAME field number; the element
//     stream for one field must be contiguous.
//   - Default values are never emitted: integer 0, bool false, empty string,
//     empty bytes, absent message. A decoder rejects an explicit default
//     (varint 0 for an integer/bool field, zero-length string/bytes) because
//     omission is the only canonical spelling.
//   - Varints are minimal: no over-long continuations, and a multi-byte varint
//     whose final byte is 0 is rejected. Varints longer than 10 bytes or
//     overflowing 64 bits are rejected.
//   - Signed integers use zigzag encoding (sint64/sint32 semantics).
//   - Booleans are encoded as varint 1 only (true); any other value is
//     rejected.
//   - Strings must be valid UTF-8 and must not contain NUL.
//   - Only wire types 0 (varint) and 2 (length-delimited) exist. Everything
//     else is rejected.
//   - Unknown fields and trailing bytes are rejected.
//
// These rules make re-encode equality structural: any accepted byte string is
// exactly what the encoder would produce for the decoded value.
package pfwire

import (
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// Wire types (protowire-compatible subset).
const (
	TypeVarint = 0
	TypeBytes  = 2
)

// ErrMalformed is the classification root for every strict-decode rejection.
var ErrMalformed = errors.New("pfwire: malformed canonical encoding")

func malformedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// AppendVarint appends v as a minimal varint.
func AppendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// SizeVarint reports the encoded size of v as a minimal varint.
func SizeVarint(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// Zigzag maps a signed value onto the unsigned varint space.
func Zigzag(v int64) uint64 { return uint64(v<<1) ^ uint64(v>>63) }

// Unzigzag inverts Zigzag.
func Unzigzag(u uint64) int64 { return int64(u>>1) ^ -int64(u&1) }

// AppendTag appends the field header for (field, wireType).
func AppendTag(dst []byte, field uint32, wireType int) []byte {
	return AppendVarint(dst, uint64(field)<<3|uint64(wireType))
}

// AppendUint emits field=v when v != 0 (default omission).
func AppendUint(dst []byte, field uint32, v uint64) []byte {
	if v == 0 {
		return dst
	}
	dst = AppendTag(dst, field, TypeVarint)
	return AppendVarint(dst, v)
}

// AppendSint emits field=v (zigzag) when v != 0.
func AppendSint(dst []byte, field uint32, v int64) []byte {
	if v == 0 {
		return dst
	}
	dst = AppendTag(dst, field, TypeVarint)
	return AppendVarint(dst, Zigzag(v))
}

// AppendBool emits field=1 when v is true.
func AppendBool(dst []byte, field uint32, v bool) []byte {
	if !v {
		return dst
	}
	dst = AppendTag(dst, field, TypeVarint)
	return append(dst, 1)
}

// AppendBytes emits field=b when b is non-empty.
func AppendBytes(dst []byte, field uint32, b []byte) []byte {
	if len(b) == 0 {
		return dst
	}
	dst = AppendTag(dst, field, TypeBytes)
	dst = AppendVarint(dst, uint64(len(b)))
	return append(dst, b...)
}

// AppendString emits field=s when s is non-empty.
func AppendString(dst []byte, field uint32, s string) []byte {
	if len(s) == 0 {
		return dst
	}
	dst = AppendTag(dst, field, TypeBytes)
	dst = AppendVarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// SizeTagged reports the size of a length-delimited field with payload n.
func SizeTagged(field uint32, n int) int {
	return SizeVarint(uint64(field)<<3|TypeBytes) + SizeVarint(uint64(n)) + n
}

// Reader is a strict sequential decoder over one message's bytes.
type Reader struct {
	buf  []byte
	pos  int
	last uint32 // last field number accepted (0 = none); enforces ascending order
	what string // message name for errors
}

// NewReader wraps one complete message body.
func NewReader(what string, buf []byte) *Reader {
	return &Reader{buf: buf, what: what}
}

// Done reports whether every byte was consumed.
func (r *Reader) Done() bool { return r.pos >= len(r.buf) }

// Remaining returns the number of unconsumed bytes.
func (r *Reader) Remaining() int { return len(r.buf) - r.pos }

// varint reads one minimal varint.
func (r *Reader) varint() (uint64, error) {
	var v uint64
	var shift uint
	start := r.pos
	for {
		if r.pos >= len(r.buf) {
			return 0, malformedf("%s: truncated varint at %d", r.what, start)
		}
		b := r.buf[r.pos]
		r.pos++
		if shift == 63 && b > 1 {
			return 0, malformedf("%s: varint overflows 64 bits at %d", r.what, start)
		}
		if shift > 63 {
			return 0, malformedf("%s: varint too long at %d", r.what, start)
		}
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			if b == 0 && shift > 0 {
				return 0, malformedf("%s: non-minimal varint at %d", r.what, start)
			}
			return v, nil
		}
		shift += 7
	}
}

// Next reads the next field header. Returns (0,0,false,nil) at end of message.
// Enforces strictly ascending field order for singular fields; a repeated
// field re-presents the SAME field number, which the caller opts into with
// NextRepeated.
func (r *Reader) Next() (field uint32, wireType int, ok bool, err error) {
	if r.Done() {
		return 0, 0, false, nil
	}
	tag, err := r.varint()
	if err != nil {
		return 0, 0, false, err
	}
	wt := int(tag & 7)
	f := tag >> 3
	if f == 0 || f > math.MaxUint32 {
		return 0, 0, false, malformedf("%s: invalid field number %d", r.what, f)
	}
	if wt != TypeVarint && wt != TypeBytes {
		return 0, 0, false, malformedf("%s: field %d has unsupported wire type %d", r.what, f, wt)
	}
	return uint32(f), wt, true, nil
}

// Require enforces the ordering invariant for a SINGULAR field: its number
// must be strictly greater than every previously accepted field.
func (r *Reader) Require(field uint32) error {
	if field <= r.last {
		return malformedf("%s: field %d out of order or duplicated (last %d)", r.what, field, r.last)
	}
	r.last = field
	return nil
}

// RequireRepeated enforces ordering for a REPEATED field: the first element
// must be strictly greater than the previous field; subsequent elements repeat
// the same number contiguously.
func (r *Reader) RequireRepeated(field uint32) error {
	if field == r.last {
		return nil // contiguous continuation
	}
	return r.Require(field)
}

// Uint decodes a varint field value, rejecting the non-canonical explicit 0.
func (r *Reader) Uint(field uint32) (uint64, error) {
	v, err := r.varint()
	if err != nil {
		return 0, err
	}
	if v == 0 {
		return 0, malformedf("%s: field %d explicitly encodes default 0", r.what, field)
	}
	return v, nil
}

// Uint32 decodes a varint bounded to 32 bits.
func (r *Reader) Uint32(field uint32) (uint32, error) {
	v, err := r.Uint(field)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint32 {
		return 0, malformedf("%s: field %d value %d overflows uint32", r.what, field, v)
	}
	return uint32(v), nil
}

// Sint decodes a zigzag varint, rejecting explicit 0.
func (r *Reader) Sint(field uint32) (int64, error) {
	v, err := r.Uint(field)
	if err != nil {
		return 0, err
	}
	return Unzigzag(v), nil
}

// Sint32 decodes a zigzag varint bounded to int32.
func (r *Reader) Sint32(field uint32) (int32, error) {
	v, err := r.Sint(field)
	if err != nil {
		return 0, err
	}
	if v > math.MaxInt32 || v < math.MinInt32 {
		return 0, malformedf("%s: field %d value %d overflows int32", r.what, field, v)
	}
	return int32(v), nil
}

// Bool decodes a canonical bool (varint exactly 1).
func (r *Reader) Bool(field uint32) (bool, error) {
	v, err := r.varint()
	if err != nil {
		return false, err
	}
	if v != 1 {
		return false, malformedf("%s: field %d bool must encode as 1 (got %d)", r.what, field, v)
	}
	return true, nil
}

// Bytes decodes a length-delimited field, rejecting the non-canonical empty
// form and enforcing max.
func (r *Reader) Bytes(field uint32, max int) ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, malformedf("%s: field %d explicitly encodes empty bytes", r.what, field)
	}
	if n > uint64(max) {
		return nil, malformedf("%s: field %d length %d exceeds bound %d", r.what, field, n, max)
	}
	if uint64(r.Remaining()) < n {
		return nil, malformedf("%s: field %d truncated (%d of %d bytes)", r.what, field, r.Remaining(), n)
	}
	out := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, nil
}

// String decodes a UTF-8, NUL-free string field.
func (r *Reader) String(field uint32, max int) (string, error) {
	b, err := r.Bytes(field, max)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", malformedf("%s: field %d is not valid UTF-8", r.what, field)
	}
	for _, c := range b {
		if c == 0 {
			return "", malformedf("%s: field %d contains NUL", r.what, field)
		}
	}
	return string(b), nil
}

// Skip is intentionally absent: unknown fields are always rejected.

// RejectUnknown returns the canonical unknown-field error.
func (r *Reader) RejectUnknown(field uint32) error {
	return malformedf("%s: unknown field %d", r.what, field)
}

// Malformedf builds a strict-decode rejection scoped to this reader's message.
func (r *Reader) Malformedf(format string, args ...any) error {
	return malformedf("%s: %s", r.what, fmt.Sprintf(format, args...))
}
