package hydrator

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/steerlabs/portablefs/vcs/archive"
)

// The authority <-> hydrator socket protocol, pinned by restore-mode.md.
//
// One AF_UNIX stream socket, length-prefixed frames of
// `u32 LE length | u8 type | payload`, where length counts the type byte and
// the payload, and no frame exceeds 16 MiB + 64 KiB. The authority connects
// with a small pool and keeps one request in flight per connection; the
// hydrator answers on the same connection in order.
//
// The contract pins the framing, the type numbers 1..7, the FETCH and CHUNK and
// ERR payloads, and the fact that the drain order is streamed in bounded pages
// via INFO_NEXT. It does not pin the byte layout of INFO_OK, the type number of
// INFO_NEXT, or the shape of a drain-order page, so this file pins them:
// INFO_NEXT is type 8 carrying a u64 cursor, its reply is DRAIN_PAGE (type 9),
// and INFO_OK carries the header facts plus the drain-order and priority
// counts. Every layout below is little-endian and fixed-width, so a reader
// validates lengths before it reads and a malformed frame is refused rather
// than partially parsed.
const (
	// MaxFrameBytes is the pinned cap on one wire frame's length field.
	MaxFrameBytes = 16<<20 + 64<<10

	// MaxConnections bounds concurrent authority connections. The authority
	// uses a small pool; the bound exists so a leak on the other side cannot
	// exhaust this process.
	MaxConnections = 64

	// DrainPageSize is how many (entryIndex, chunkIndex) pairs one INFO_NEXT
	// page carries: 8192 pairs is a 64 KiB payload, comfortably inside the
	// frame cap and large enough that a full drain order of a large volume
	// takes few round trips.
	DrainPageSize = 8192
)

// MessageType is the frame type byte.
type MessageType uint8

const (
	TypeInfo      MessageType = 1
	TypeInfoOK    MessageType = 2
	TypeFetch     MessageType = 3
	TypeChunk     MessageType = 4
	TypeErr       MessageType = 5
	TypeHealth    MessageType = 6
	TypeHealthOK  MessageType = 7
	TypeInfoNext  MessageType = 8
	TypeDrainPage MessageType = 9
)

func (t MessageType) String() string {
	switch t {
	case TypeInfo:
		return "INFO"
	case TypeInfoOK:
		return "INFO_OK"
	case TypeFetch:
		return "FETCH"
	case TypeChunk:
		return "CHUNK"
	case TypeErr:
		return "ERR"
	case TypeHealth:
		return "HEALTH"
	case TypeHealthOK:
		return "HEALTH_OK"
	case TypeInfoNext:
		return "INFO_NEXT"
	case TypeDrainPage:
		return "DRAIN_PAGE"
	default:
		return fmt.Sprintf("type(%d)", uint8(t))
	}
}

// ErrorClass is the pinned ERR classification. The three classes mean three
// different things to the authority: blocked is volume-wide and auto-clearing,
// corrupt is a data-integrity event, and invalid is a protocol fault.
type ErrorClass uint8

const (
	ErrorBlocked ErrorClass = 1
	ErrorCorrupt ErrorClass = 2
	ErrorInvalid ErrorClass = 3
)

func (c ErrorClass) String() string {
	switch c {
	case ErrorBlocked:
		return "blocked"
	case ErrorCorrupt:
		return "corrupt"
	case ErrorInvalid:
		return "invalid"
	default:
		return "unknown"
	}
}

// ErrProtocol marks a frame that violated the wire contract: an impossible
// length, a truncated payload, a payload that does not match its type.
var ErrProtocol = errors.New("hydrator: protocol violation")

// MaxErrorMessageBytes bounds an ERR message so a failure cannot become a
// denial of service on the reader.
const MaxErrorMessageBytes = 1024

// WriteFrame writes one frame. The payload must already be inside the cap; a
// caller that would exceed it has built a message it must not send.
func WriteFrame(writer io.Writer, kind MessageType, payload []byte) error {
	if len(payload)+1 > MaxFrameBytes {
		return fmt.Errorf("%w: a %s frame of %d bytes exceeds the cap", ErrProtocol, kind, len(payload)+1)
	}
	header := make([]byte, 5)
	binary.LittleEndian.PutUint32(header[:4], uint32(len(payload)+1))
	header[4] = byte(kind)
	if _, err := writer.Write(header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := writer.Write(payload)
	return err
}

// ReadFrame reads one frame, refusing an impossible length before allocating
// for it. An oversized length is a protocol violation and not something to skip
// past: the stream's framing can no longer be trusted, so the caller closes.
func ReadFrame(reader io.Reader) (MessageType, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	length := binary.LittleEndian.Uint32(header[:])
	if length < 1 {
		return 0, nil, fmt.Errorf("%w: frame length %d is below the one-byte type", ErrProtocol, length)
	}
	if length > MaxFrameBytes {
		return 0, nil, fmt.Errorf("%w: frame length %d exceeds the %d byte cap", ErrProtocol, length, MaxFrameBytes)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return 0, nil, err
	}
	return MessageType(body[0]), body[1:], nil
}

// Info is the INFO_OK payload: everything the authority needs before it can
// interpret a single chunk, plus the drain-order counts it pages through.
//
// Layout, all little-endian:
//
//	formatVersion u32 | volumeID 16B | sealedEpoch u64 | attempt 16B |
//	chunkSizeBytes u32 | entryCount u32 | chunkCount u64 | logicalBytes u64 |
//	logicalInodes u64 | sealedAllocatedBytes u64 | sealedInodes u64 |
//	priorityPackIndex u32 | priorityPackOffset u64 | drainCount u64 |
//	priorityDrainCount u64 | pageSize u32
type Info struct {
	FormatVersion        uint32
	VolumeID             [16]byte
	SealedEpoch          uint64
	Attempt              [16]byte
	ChunkSizeBytes       uint32
	EntryCount           uint32
	ChunkCount           uint64
	LogicalBytes         uint64
	LogicalInodes        uint64
	SealedAllocatedBytes uint64
	SealedInodes         uint64
	PriorityPackIndex    uint32
	PriorityPackOffset   uint64
	// DrainCount is the number of (entryIndex, chunkIndex) pairs in the drain
	// order; PriorityDrainCount is how many of the leading pairs lie inside the
	// wake-prefetch region, which is the landmark the authority drains first.
	DrainCount         uint64
	PriorityDrainCount uint64
	PageSize           uint32
}

const infoPayloadBytes = 4 + 16 + 8 + 16 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 4 + 8 + 8 + 8 + 4

// Encode renders the INFO_OK payload.
func (i Info) Encode() []byte {
	out := make([]byte, 0, infoPayloadBytes)
	out = binary.LittleEndian.AppendUint32(out, i.FormatVersion)
	out = append(out, i.VolumeID[:]...)
	out = binary.LittleEndian.AppendUint64(out, i.SealedEpoch)
	out = append(out, i.Attempt[:]...)
	out = binary.LittleEndian.AppendUint32(out, i.ChunkSizeBytes)
	out = binary.LittleEndian.AppendUint32(out, i.EntryCount)
	out = binary.LittleEndian.AppendUint64(out, i.ChunkCount)
	out = binary.LittleEndian.AppendUint64(out, i.LogicalBytes)
	out = binary.LittleEndian.AppendUint64(out, i.LogicalInodes)
	out = binary.LittleEndian.AppendUint64(out, i.SealedAllocatedBytes)
	out = binary.LittleEndian.AppendUint64(out, i.SealedInodes)
	out = binary.LittleEndian.AppendUint32(out, i.PriorityPackIndex)
	out = binary.LittleEndian.AppendUint64(out, i.PriorityPackOffset)
	out = binary.LittleEndian.AppendUint64(out, i.DrainCount)
	out = binary.LittleEndian.AppendUint64(out, i.PriorityDrainCount)
	out = binary.LittleEndian.AppendUint32(out, i.PageSize)
	return out
}

// DecodeInfo parses an INFO_OK payload, refusing anything but the exact length.
func DecodeInfo(payload []byte) (Info, error) {
	if len(payload) != infoPayloadBytes {
		return Info{}, fmt.Errorf("%w: INFO_OK payload is %d bytes, expected %d", ErrProtocol, len(payload), infoPayloadBytes)
	}
	cursor := newCursor(payload)
	info := Info{FormatVersion: cursor.uint32()}
	copy(info.VolumeID[:], cursor.bytes(16))
	info.SealedEpoch = cursor.uint64()
	copy(info.Attempt[:], cursor.bytes(16))
	info.ChunkSizeBytes = cursor.uint32()
	info.EntryCount = cursor.uint32()
	info.ChunkCount = cursor.uint64()
	info.LogicalBytes = cursor.uint64()
	info.LogicalInodes = cursor.uint64()
	info.SealedAllocatedBytes = cursor.uint64()
	info.SealedInodes = cursor.uint64()
	info.PriorityPackIndex = cursor.uint32()
	info.PriorityPackOffset = cursor.uint64()
	info.DrainCount = cursor.uint64()
	info.PriorityDrainCount = cursor.uint64()
	info.PageSize = cursor.uint32()
	return info, nil
}

// DrainPair is one unit of the drain order: which entry, and which of its
// chunks. Pairs are in pack order, so draining them in sequence is one
// sequential sweep over the pack objects.
type DrainPair struct {
	EntryIndex uint32
	ChunkIndex uint32
}

// DrainPage is one INFO_NEXT reply: the pairs starting at the requested cursor,
// and whether more follow.
//
// Layout: `cursor u64 | count u32 | (entryIndex u32, chunkIndex u32)... | more u8`.
type DrainPage struct {
	Cursor uint64
	Pairs  []DrainPair
	More   bool
}

// Encode renders the DRAIN_PAGE payload.
func (p DrainPage) Encode() []byte {
	out := make([]byte, 0, 8+4+len(p.Pairs)*8+1)
	out = binary.LittleEndian.AppendUint64(out, p.Cursor)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(p.Pairs)))
	for _, pair := range p.Pairs {
		out = binary.LittleEndian.AppendUint32(out, pair.EntryIndex)
		out = binary.LittleEndian.AppendUint32(out, pair.ChunkIndex)
	}
	if p.More {
		return append(out, 1)
	}
	return append(out, 0)
}

// DecodeDrainPage parses a DRAIN_PAGE payload. The pair count is checked
// against the bytes actually present before anything is allocated.
func DecodeDrainPage(payload []byte) (DrainPage, error) {
	if len(payload) < 13 {
		return DrainPage{}, fmt.Errorf("%w: DRAIN_PAGE payload is %d bytes", ErrProtocol, len(payload))
	}
	cursor := newCursor(payload)
	page := DrainPage{Cursor: cursor.uint64()}
	count := cursor.uint32()
	if uint64(count) > uint64(DrainPageSize) {
		return DrainPage{}, fmt.Errorf("%w: DRAIN_PAGE carries %d pairs, the page size is %d", ErrProtocol, count, DrainPageSize)
	}
	if len(payload) != 8+4+int(count)*8+1 {
		return DrainPage{}, fmt.Errorf("%w: DRAIN_PAGE payload does not match its pair count", ErrProtocol)
	}
	page.Pairs = make([]DrainPair, count)
	for index := range page.Pairs {
		page.Pairs[index] = DrainPair{EntryIndex: cursor.uint32(), ChunkIndex: cursor.uint32()}
	}
	page.More = cursor.bytes(1)[0] == 1
	return page, nil
}

// EncodeFetch renders the FETCH payload: `entryIndex u32 | chunkIndex u32`.
func EncodeFetch(entryIndex, chunkIndex uint32) []byte {
	out := make([]byte, 0, 8)
	out = binary.LittleEndian.AppendUint32(out, entryIndex)
	return binary.LittleEndian.AppendUint32(out, chunkIndex)
}

// DecodeFetch parses a FETCH payload.
func DecodeFetch(payload []byte) (entryIndex, chunkIndex uint32, err error) {
	if len(payload) != 8 {
		return 0, 0, fmt.Errorf("%w: FETCH payload is %d bytes, expected 8", ErrProtocol, len(payload))
	}
	return binary.LittleEndian.Uint32(payload[:4]), binary.LittleEndian.Uint32(payload[4:]), nil
}

// EncodeCursor renders the INFO_NEXT payload: `cursor u64`.
func EncodeCursor(cursor uint64) []byte {
	return binary.LittleEndian.AppendUint64(make([]byte, 0, 8), cursor)
}

// DecodeCursor parses an INFO_NEXT payload.
func DecodeCursor(payload []byte) (uint64, error) {
	if len(payload) != 8 {
		return 0, fmt.Errorf("%w: INFO_NEXT payload is %d bytes, expected 8", ErrProtocol, len(payload))
	}
	return binary.LittleEndian.Uint64(payload), nil
}

// Chunk is a CHUNK reply: the chunk's data extents inside its logical span, and
// the stored bytes those extents describe, concatenated in offset order. The
// authority writes each extent's bytes at its offset within the chunk; the
// holes it does not write are already holes in the restored file.
//
// Layout: `extentCount u32 | (offsetInChunk u64, length u64)... | data`, where
// the data runs to the end of the frame. A chunk that lies wholly inside a hole
// is a valid reply with no extents and no data: it is born hydrated.
type Chunk struct {
	Extents []archive.Extent
	Data    []byte
}

// Encode renders the CHUNK payload.
func (c Chunk) Encode() []byte {
	out := make([]byte, 0, 4+len(c.Extents)*16+len(c.Data))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(c.Extents)))
	for _, extent := range c.Extents {
		out = binary.LittleEndian.AppendUint64(out, extent.Offset)
		out = binary.LittleEndian.AppendUint64(out, extent.Length)
	}
	return append(out, c.Data...)
}

// DecodeChunk parses a CHUNK payload and proves it internally consistent: the
// extent count fits the payload, the extents are ordered, non-empty,
// non-adjacent, and inside the chunk size, and their lengths sum to exactly the
// data carried. An inconsistent reply is refused rather than written.
func DecodeChunk(payload []byte, chunkSize uint64) (Chunk, error) {
	if len(payload) < 4 {
		return Chunk{}, fmt.Errorf("%w: CHUNK payload is %d bytes", ErrProtocol, len(payload))
	}
	cursor := newCursor(payload)
	count := cursor.uint32()
	if uint64(count) > uint64(archive.MaxExtentsPerChunk) {
		return Chunk{}, fmt.Errorf("%w: CHUNK carries %d extents, the bound is %d", ErrProtocol, count, archive.MaxExtentsPerChunk)
	}
	if len(payload) < 4+int(count)*16 {
		return Chunk{}, fmt.Errorf("%w: CHUNK payload is shorter than its extent count", ErrProtocol)
	}
	chunk := Chunk{Extents: make([]archive.Extent, count)}
	stored := uint64(0)
	previousEnd := uint64(0)
	for index := range chunk.Extents {
		extent := archive.Extent{Offset: cursor.uint64(), Length: cursor.uint64()}
		switch {
		case extent.Length == 0:
			return Chunk{}, fmt.Errorf("%w: CHUNK extent %d is empty", ErrProtocol, index)
		case index > 0 && extent.Offset <= previousEnd:
			return Chunk{}, fmt.Errorf("%w: CHUNK extent %d is not strictly after and apart from its predecessor", ErrProtocol, index)
		case extent.Offset+extent.Length < extent.Offset || extent.Offset+extent.Length > chunkSize:
			return Chunk{}, fmt.Errorf("%w: CHUNK extent %d runs past the chunk", ErrProtocol, index)
		}
		previousEnd = extent.Offset + extent.Length
		stored += extent.Length
		chunk.Extents[index] = extent
	}
	chunk.Data = payload[4+int(count)*16:]
	if uint64(len(chunk.Data)) != stored {
		return Chunk{}, fmt.Errorf("%w: CHUNK carries %d bytes for extents covering %d", ErrProtocol, len(chunk.Data), stored)
	}
	return chunk, nil
}

// EncodeError renders the ERR payload: `class u8 | message`.
func EncodeError(class ErrorClass, message string) []byte {
	if len(message) > MaxErrorMessageBytes {
		message = message[:MaxErrorMessageBytes]
	}
	return append([]byte{byte(class)}, message...)
}

// DecodeError parses an ERR payload.
func DecodeError(payload []byte) (ErrorClass, string, error) {
	if len(payload) < 1 {
		return 0, "", fmt.Errorf("%w: ERR payload is empty", ErrProtocol)
	}
	class := ErrorClass(payload[0])
	switch class {
	case ErrorBlocked, ErrorCorrupt, ErrorInvalid:
	default:
		return 0, "", fmt.Errorf("%w: ERR class %d is not one of the pinned three", ErrProtocol, payload[0])
	}
	if len(payload) > 1+MaxErrorMessageBytes {
		return 0, "", fmt.Errorf("%w: ERR message exceeds %d bytes", ErrProtocol, MaxErrorMessageBytes)
	}
	return class, string(payload[1:]), nil
}

// cursor is a fixed-width little-endian reader over a payload whose length has
// already been checked. Every use validates the total length first, so the
// reader itself never has to fail.
type cursor struct {
	buf []byte
	at  int
}

func newCursor(buf []byte) *cursor { return &cursor{buf: buf} }

func (c *cursor) bytes(n int) []byte {
	out := c.buf[c.at : c.at+n]
	c.at += n
	return out
}

func (c *cursor) uint32() uint32 { return binary.LittleEndian.Uint32(c.bytes(4)) }

func (c *cursor) uint64() uint64 { return binary.LittleEndian.Uint64(c.bytes(8)) }
