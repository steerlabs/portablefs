package restoremode

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	FrameInfo      byte = 1
	FrameInfoOK    byte = 2
	FrameFetch     byte = 3
	FrameChunk     byte = 4
	FrameError     byte = 5
	FrameHealth    byte = 6
	FrameHealthOK  byte = 7
	FrameInfoNext  byte = 8
	FrameDrainPage byte = 9
)

const (
	ErrorBlocked byte = 1
	ErrorCorrupt byte = 2
	ErrorInvalid byte = 3
)

// InfoPage contains the fixed-width INFO_OK header and the drain order assembled
// from subsequent DRAIN_PAGE replies. UUIDs are exposed in their canonical
// textual form to compare directly with the sealed state records.
type InfoPage struct {
	FormatVersion      uint32
	VolumeID           string
	SealedEpoch        uint64
	Attempt            string
	ChunkSize          uint32
	EntryCount         uint32
	ChunkCount         uint64
	LogicalBytes       uint64
	LogicalInodes      uint64
	StoredBytes        uint64
	SealedInodes       uint64
	PriorityPackIndex  uint32
	PriorityPackOffset uint64
	DrainCount         uint64
	PriorityDrainCount uint64
	PageSize           uint32
	Order              [][2]uint32
}

const infoPayloadBytes = 4 + 16 + 8 + 16 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 4 + 8 + 8 + 8 + 4

func MarshalInfoPage(page InfoPage) ([]byte, error) {
	volume, err := parseUUID(page.VolumeID)
	if err != nil {
		return nil, ErrProtocol
	}
	attempt, err := parseUUID(page.Attempt)
	if err != nil {
		return nil, ErrProtocol
	}
	out := make([]byte, 0, infoPayloadBytes)
	out = appendU32(out, page.FormatVersion)
	out = append(out, volume[:]...)
	out = appendU64(out, page.SealedEpoch)
	out = append(out, attempt[:]...)
	out = appendU32(out, page.ChunkSize)
	out = appendU32(out, page.EntryCount)
	out = appendU64(out, page.ChunkCount)
	out = appendU64(out, page.LogicalBytes)
	out = appendU64(out, page.LogicalInodes)
	out = appendU64(out, page.StoredBytes)
	out = appendU64(out, page.SealedInodes)
	out = appendU32(out, page.PriorityPackIndex)
	out = appendU64(out, page.PriorityPackOffset)
	out = appendU64(out, page.DrainCount)
	out = appendU64(out, page.PriorityDrainCount)
	out = appendU32(out, page.PageSize)
	return out, nil
}

func UnmarshalInfoPage(raw []byte) (InfoPage, error) {
	if len(raw) != infoPayloadBytes {
		return InfoPage{}, fmt.Errorf("%w: malformed INFO_OK length", ErrProtocol)
	}
	decoder := wireDecoder{raw: raw}
	var page InfoPage
	page.FormatVersion = decoder.u32()
	var volume [16]byte
	copy(volume[:], decoder.take(16))
	page.VolumeID = formatUUID(volume)
	page.SealedEpoch = decoder.u64()
	var attempt [16]byte
	copy(attempt[:], decoder.take(16))
	page.Attempt = formatUUID(attempt)
	page.ChunkSize = decoder.u32()
	page.EntryCount = decoder.u32()
	page.ChunkCount = decoder.u64()
	page.LogicalBytes = decoder.u64()
	page.LogicalInodes = decoder.u64()
	page.StoredBytes = decoder.u64()
	page.SealedInodes = decoder.u64()
	page.PriorityPackIndex = decoder.u32()
	page.PriorityPackOffset = decoder.u64()
	page.DrainCount = decoder.u64()
	page.PriorityDrainCount = decoder.u64()
	page.PageSize = decoder.u32()
	if decoder.err != nil || decoder.off != len(raw) {
		return InfoPage{}, fmt.Errorf("%w: malformed INFO_OK", ErrProtocol)
	}
	return page, nil
}

type drainPage struct {
	Cursor uint64
	Order  [][2]uint32
	More   bool
}

func marshalDrainPage(page drainPage) ([]byte, error) {
	if len(page.Order) > 8192 {
		return nil, ErrProtocol
	}
	out := appendU64(nil, page.Cursor)
	out = appendU32(out, uint32(len(page.Order)))
	for _, pair := range page.Order {
		out = appendU32(out, pair[0])
		out = appendU32(out, pair[1])
	}
	if page.More {
		return append(out, 1), nil
	}
	return append(out, 0), nil
}

func unmarshalDrainPage(raw []byte) (drainPage, error) {
	if len(raw) < 13 {
		return drainPage{}, ErrProtocol
	}
	decoder := wireDecoder{raw: raw}
	page := drainPage{Cursor: decoder.u64()}
	count := decoder.u32()
	if count > 8192 || len(raw) != 8+4+int(count)*8+1 {
		return drainPage{}, ErrProtocol
	}
	page.Order = make([][2]uint32, count)
	for i := range page.Order {
		page.Order[i] = [2]uint32{decoder.u32(), decoder.u32()}
	}
	more := decoder.take(1)
	if len(more) != 1 || more[0] > 1 {
		return drainPage{}, ErrProtocol
	}
	page.More = more[0] == 1
	return page, nil
}

func MarshalChunk(chunk Chunk, chunkSize uint32) ([]byte, error) {
	if len(chunk.Extents) > int(^uint32(0)) {
		return nil, ErrProtocol
	}
	out := appendU32(nil, uint32(len(chunk.Extents)))
	var priorEnd uint64
	for _, extent := range chunk.Extents {
		end := extent.Offset + uint64(len(extent.Data))
		if len(extent.Data) == 0 || end < extent.Offset || end > uint64(chunkSize) || (priorEnd != 0 && extent.Offset <= priorEnd) {
			return nil, ErrProtocol
		}
		out = appendU64(out, extent.Offset)
		out = appendU64(out, uint64(len(extent.Data)))
		priorEnd = end
	}
	for _, extent := range chunk.Extents {
		out = append(out, extent.Data...)
	}
	return out, nil
}

func UnmarshalChunk(raw []byte, chunkSize uint32) (Chunk, error) {
	decoder := wireDecoder{raw: raw}
	count := decoder.u32()
	if count > 1<<20 || uint64(count)*16 > uint64(len(raw)) {
		return Chunk{}, fmt.Errorf("%w: invalid CHUNK extent count", ErrProtocol)
	}
	type span struct{ off, length uint64 }
	spans := make([]span, count)
	var total, priorEnd uint64
	for i := range spans {
		spans[i] = span{off: decoder.u64(), length: decoder.u64()}
		end := spans[i].off + spans[i].length
		if spans[i].length == 0 || end < spans[i].off || end > uint64(chunkSize) || (i > 0 && spans[i].off <= priorEnd) {
			decoder.err = ErrProtocol
		}
		priorEnd = end
		total += spans[i].length
		if total > uint64(chunkSize) {
			decoder.err = ErrProtocol
		}
	}
	if decoder.err != nil || total != uint64(len(raw)-decoder.off) {
		return Chunk{}, fmt.Errorf("%w: malformed CHUNK", ErrProtocol)
	}
	chunk := Chunk{Extents: make([]Extent, count), Bytes: total}
	for i, span := range spans {
		chunk.Extents[i].Offset = span.off
		chunk.Extents[i].Data = append([]byte(nil), raw[decoder.off:decoder.off+int(span.length)]...)
		decoder.off += int(span.length)
	}
	return chunk, nil
}

func MarshalProtocolError(class byte, message string) ([]byte, error) {
	if class < ErrorBlocked || class > ErrorInvalid || len(message) > 1024 {
		return nil, ErrProtocol
	}
	return append([]byte{class}, []byte(message)...), nil
}

func parseProtocolError(raw []byte) error {
	if len(raw) < 1 || len(raw) > 1025 {
		return ErrProtocol
	}
	detail := string(raw[1:])
	switch raw[0] {
	case ErrorBlocked:
		return &stateError{base: ErrBlocked, detail: detail}
	case ErrorCorrupt:
		return &stateError{base: ErrCorrupt, detail: detail}
	case ErrorInvalid:
		return fmt.Errorf("%w: hydrator rejected request: %s", ErrProtocol, detail)
	default:
		return ErrProtocol
	}
}

func appendU32(dst []byte, value uint32) []byte {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	return append(dst, raw[:]...)
}

func appendU64(dst []byte, value uint64) []byte {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], value)
	return append(dst, raw[:]...)
}

func parseUUID(value string) ([16]byte, error) {
	var out [16]byte
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return out, ErrProtocol
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(raw) != len(out) {
		return out, ErrProtocol
	}
	copy(out[:], raw)
	return out, nil
}

func formatUUID(value [16]byte) string {
	raw := hex.EncodeToString(value[:])
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
}

type wireDecoder struct {
	raw []byte
	off int
	err error
}

func (d *wireDecoder) take(n int) []byte {
	if d.err != nil || n < 0 || n > len(d.raw)-d.off {
		d.err = errors.New("short wire payload")
		return nil
	}
	value := d.raw[d.off : d.off+n]
	d.off += n
	return value
}

func (d *wireDecoder) u32() uint32 {
	raw := d.take(4)
	if raw == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(raw)
}

func (d *wireDecoder) u64() uint64 {
	raw := d.take(8)
	if raw == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(raw)
}
