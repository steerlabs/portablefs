package hydrator

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/steerlabs/portablefs/vcs/archive"
)

func TestFramingRoundTrips(t *testing.T) {
	var wire bytes.Buffer
	payload := []byte("a payload of no particular shape")
	if err := WriteFrame(&wire, TypeChunk, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := WriteFrame(&wire, TypeHealthOK, nil); err != nil {
		t.Fatalf("write an empty frame: %v", err)
	}
	kind, body, err := ReadFrame(&wire)
	if err != nil || kind != TypeChunk || !bytes.Equal(body, payload) {
		t.Fatalf("first frame = %s %q %v", kind, body, err)
	}
	if kind, body, err = ReadFrame(&wire); err != nil || kind != TypeHealthOK || len(body) != 0 {
		t.Fatalf("second frame = %s %q %v", kind, body, err)
	}
	if _, _, err := ReadFrame(&wire); !errors.Is(err, io.EOF) {
		t.Fatalf("a spent stream reported %v", err)
	}
}

func TestFramingRefusesImpossibleLengths(t *testing.T) {
	oversized := make([]byte, 4)
	binary.LittleEndian.PutUint32(oversized, MaxFrameBytes+1)
	if _, _, err := ReadFrame(bytes.NewReader(oversized)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("an oversized frame length was accepted: %v", err)
	}
	empty := make([]byte, 4)
	if _, _, err := ReadFrame(bytes.NewReader(empty)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a frame with no type byte was accepted: %v", err)
	}
	truncated := make([]byte, 4)
	binary.LittleEndian.PutUint32(truncated, 64)
	if _, _, err := ReadFrame(bytes.NewReader(append(truncated, 1, 2, 3))); err == nil {
		t.Fatal("a truncated frame was accepted")
	}
	if err := WriteFrame(io.Discard, TypeChunk, make([]byte, MaxFrameBytes)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("an oversized frame was written: %v", err)
	}
}

func TestInfoRoundTrips(t *testing.T) {
	info := Info{
		FormatVersion:        1,
		VolumeID:             [16]byte{1, 2, 3},
		SealedEpoch:          9,
		Attempt:              [16]byte{4, 5, 6},
		ChunkSizeBytes:       8 << 20,
		EntryCount:           4242,
		ChunkCount:           99,
		LogicalBytes:         1 << 40,
		LogicalInodes:        7,
		SealedAllocatedBytes: 1 << 30,
		SealedInodes:         4242,
		PriorityPackIndex:    2,
		PriorityPackOffset:   4096,
		DrainCount:           99,
		PriorityDrainCount:   17,
		PageSize:             DrainPageSize,
	}
	decoded, err := DecodeInfo(info.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != info {
		t.Fatal("INFO_OK does not round-trip")
	}
	if _, err := DecodeInfo(info.Encode()[:infoPayloadBytes-1]); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a short INFO_OK was accepted: %v", err)
	}
}

func TestDrainPageRoundTrips(t *testing.T) {
	page := DrainPage{Cursor: 8, Pairs: []DrainPair{{1, 0}, {1, 1}, {7, 3}}, More: true}
	decoded, err := DecodeDrainPage(page.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Cursor != page.Cursor || decoded.More != page.More || len(decoded.Pairs) != len(page.Pairs) {
		t.Fatal("DRAIN_PAGE does not round-trip")
	}
	for index, pair := range decoded.Pairs {
		if pair != page.Pairs[index] {
			t.Fatalf("pair %d does not round-trip", index)
		}
	}
	damaged := page.Encode()
	binary.LittleEndian.PutUint32(damaged[8:12], 1000)
	if _, err := DecodeDrainPage(damaged); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a page whose count does not match its bytes was accepted: %v", err)
	}
	empty := DrainPage{Cursor: 3}
	if decoded, err = DecodeDrainPage(empty.Encode()); err != nil || len(decoded.Pairs) != 0 || decoded.More {
		t.Fatalf("an empty final page does not round-trip: %v", err)
	}
}

func TestChunkRoundTripsAndRefusesInconsistency(t *testing.T) {
	chunk := Chunk{
		Extents: []archive.Extent{{Offset: 0, Length: 4}, {Offset: 16, Length: 2}},
		Data:    []byte("abcdef"),
	}
	decoded, err := DecodeChunk(chunk.Encode(), 4096)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded.Data, chunk.Data) || len(decoded.Extents) != 2 {
		t.Fatal("CHUNK does not round-trip")
	}
	empty := Chunk{}
	if decoded, err = DecodeChunk(empty.Encode(), 4096); err != nil || len(decoded.Extents) != 0 || len(decoded.Data) != 0 {
		t.Fatalf("a whole-hole chunk does not round-trip: %v", err)
	}

	short := Chunk{Extents: []archive.Extent{{Offset: 0, Length: 8}}, Data: []byte("abc")}
	if _, err := DecodeChunk(short.Encode(), 4096); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a chunk whose extents do not cover its data was accepted: %v", err)
	}
	past := Chunk{Extents: []archive.Extent{{Offset: 4090, Length: 8}}, Data: make([]byte, 8)}
	if _, err := DecodeChunk(past.Encode(), 4096); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a chunk with an extent past its span was accepted: %v", err)
	}
	unordered := Chunk{
		Extents: []archive.Extent{{Offset: 16, Length: 2}, {Offset: 0, Length: 4}},
		Data:    []byte("abcdef"),
	}
	if _, err := DecodeChunk(unordered.Encode(), 4096); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a chunk with unordered extents was accepted: %v", err)
	}
	adjacent := Chunk{
		Extents: []archive.Extent{{Offset: 0, Length: 4}, {Offset: 4, Length: 4}},
		Data:    []byte("abcdefgh"),
	}
	if _, err := DecodeChunk(adjacent.Encode(), 4096); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a chunk with adjacent extents was accepted; the extent map must be canonical: %v", err)
	}
}

func TestErrorPayloads(t *testing.T) {
	for _, class := range []ErrorClass{ErrorBlocked, ErrorCorrupt, ErrorInvalid} {
		decoded, message, err := DecodeError(EncodeError(class, "why"))
		if err != nil || decoded != class || message != "why" {
			t.Fatalf("ERR does not round-trip for %s: %v", class, err)
		}
	}
	if _, _, err := DecodeError(nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("an empty ERR was accepted: %v", err)
	}
	if _, _, err := DecodeError([]byte{9}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("an unknown ERR class was accepted: %v", err)
	}
	long := EncodeError(ErrorBlocked, string(make([]byte, MaxErrorMessageBytes*2)))
	if len(long) != 1+MaxErrorMessageBytes {
		t.Fatalf("an ERR message of %d bytes was not truncated to the bound", len(long)-1)
	}
}

func TestFetchAndCursorPayloads(t *testing.T) {
	entry, chunk, err := DecodeFetch(EncodeFetch(7, 3))
	if err != nil || entry != 7 || chunk != 3 {
		t.Fatalf("FETCH does not round-trip: %v", err)
	}
	if _, _, err := DecodeFetch([]byte{1, 2, 3}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a short FETCH was accepted: %v", err)
	}
	cursor, err := DecodeCursor(EncodeCursor(1 << 40))
	if err != nil || cursor != 1<<40 {
		t.Fatalf("INFO_NEXT does not round-trip: %v", err)
	}
	if _, err := DecodeCursor(nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("an empty INFO_NEXT was accepted: %v", err)
	}
}

// TestDrainPagingCoversTheOrder drives the paging arithmetic directly, over an
// order long enough to need several pages — the shape a large volume produces
// and a round-trip test over a small tree never reaches.
func TestDrainPagingCoversTheOrder(t *testing.T) {
	server := &Server{drain: make([]DrainPair, DrainPageSize*2+7)}
	for index := range server.drain {
		server.drain[index] = DrainPair{EntryIndex: uint32(index), ChunkIndex: uint32(index % 3)}
	}
	seen := 0
	for cursor := uint64(0); ; {
		page, err := server.page(cursor)
		if err != nil {
			t.Fatalf("page at %d: %v", cursor, err)
		}
		if len(page.Pairs) > DrainPageSize {
			t.Fatalf("a page carried %d pairs", len(page.Pairs))
		}
		for index, pair := range page.Pairs {
			if pair != server.drain[int(cursor)+index] {
				t.Fatalf("page at %d does not match the order", cursor)
			}
		}
		seen += len(page.Pairs)
		cursor += uint64(len(page.Pairs))
		if !page.More {
			break
		}
	}
	if seen != len(server.drain) {
		t.Fatalf("paging covered %d of %d pairs", seen, len(server.drain))
	}
	if _, err := server.page(uint64(len(server.drain)) + 1); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a cursor past the order was accepted: %v", err)
	}
	final, err := server.page(uint64(len(server.drain)))
	if err != nil || len(final.Pairs) != 0 || final.More {
		t.Fatalf("the cursor at the end is not an empty final page: %v", err)
	}
}
