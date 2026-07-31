package fsproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func encodeRequestForTest(t *testing.T, req *Request) []byte {
	t.Helper()
	var wire bytes.Buffer
	if err := newRequestEncoder(&wire).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	return wire.Bytes()
}

func decodeRequestForTest(wire []byte) (Request, error) {
	var req Request
	err := newRequestDecoder(bytes.NewReader(wire)).Decode(&req)
	return req, err
}

func TestRequestCodecRoundTripAllFields(t *testing.T) {
	reqHash := bytes.Repeat([]byte{0xa5}, 32)
	want := Request{
		Op: OpFlushBatch,

		Path:         "scope/file",
		NewPath:      "scope/new",
		OrphanTarget: true,
		Offset:       -17,
		Size:         -23,
		Mode:         0o6754,
		Target:       "target",
		Data:         []byte("payload"),
		Append:       true,
		MtimeMs:      -29,
		AtimeMs:      -30,
		SetMode:      true,
		SetTime:      true,
		SetATime:     true,
		UID:          31,
		GID:          37,
		SetUID:       true,
		SetGID:       true,
		Owner:        "owner",

		SessionID: "writeback",
		Epoch:     41,
		Records: []wal.Record{{
			Seq: 43, Op: wal.OpWrite, Path: "scope/file", Offset: 47, Data: []byte("record"),
		}},

		LkID:     53,
		LkStart:  59,
		LkEnd:    61,
		LkWrite:  true,
		LkUnlock: true,
		LkMode:   LkSetlkw,

		OrphanIno:    67,
		HandleIno:    71,
		OrphanInos:   []uint64{73, 79},
		OpenIno:      83,
		OpenState:    true,
		OpenInos:     []uint64{89, 97},
		OpenPaths:    []string{"scope/file", "scope/peer"},
		RegisterOpen: true,

		SessionGen:   101,
		SessionToken: "token",
		SessionSlots: 103,
		Env: &wal.Envelope{
			SessionID: "mount-session", Generation: 107, Slot: 109, SlotSeq: 113, ReqHash: reqHash,
		},

		CheckoutPath:  "scope",
		CheckoutEpoch: "epoch",
		Excl:          true,
		XattrName:     "user.key",
		XattrFlags:    wal.XattrCreate,

		WBPrevDigest: []byte("previous"),
		WBEndDigest:  []byte("end"),
		WBScopes:     []WBScope{{Path: "scope", Epoch: "epoch", Through: 125}},
		WBThrough:    127,
		AckPos:       131,

		Flags:    0x8000_0002,
		SetFlags: true,
	}
	got, err := decodeRequestForTest(encodeRequestForTest(t, &want))
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request round trip mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

// requestOffsets locates the two version-gated scalars inside a current-version
// frame: the v3 atime (8 bytes) and the v4 chflags word (4 bytes, last of the
// fixed scalar block, right after AckPos).
const (
	requestVersionOffset = 4 + 4
	requestAtimeOffset   = 4 + 4 + 1 + 1 + 4 + 8 + 8 + 4 + 8
	requestFlagsOffset   = requestAtimeOffset + 8 + 4 + 4 + 8 + 8 + 8 + 8 + 1 + 8 + 8 + 8 + 8 + 4 + 1 + 8 + 8
)

// downgradeRequestWire rewrites a current-version frame as an older peer would
// have written it, stripping exactly the scalars that version had not appended
// yet. It is how the codec's backward compatibility stays provable as fields
// are appended: each older version is decoded from bytes shaped like its own.
func downgradeRequestWire(t *testing.T, wire []byte, version uint8) []byte {
	t.Helper()
	if len(wire) < requestFlagsOffset+4 {
		t.Fatalf("short request frame: %d bytes", len(wire))
	}
	out := append([]byte(nil), wire...)
	stripped := 0
	strip := func(offset, width int) {
		out = append(out[:offset], out[offset+width:]...)
		stripped += width
	}
	if version < requestWireChflagsVersion {
		strip(requestFlagsOffset, 4)
	}
	if version < requestWireAtimeVersion {
		strip(requestAtimeOffset, 8)
	}
	bodyBytes := binary.BigEndian.Uint32(wire[:4])
	if int(bodyBytes) < stripped {
		t.Fatalf("invalid body size: %d", bodyBytes)
	}
	out[requestVersionOffset] = version
	binary.BigEndian.PutUint32(out[:4], bodyBytes-uint32(stripped))
	return out
}

func TestRequestDecoderAcceptsLegacyV2(t *testing.T) {
	want := Request{
		Op:           OpSetattr,
		Path:         "scope/file",
		Size:         41,
		Mode:         0o640,
		MtimeMs:      1700000000123,
		SetMode:      true,
		SetTime:      true,
		UID:          43,
		GID:          47,
		SetUID:       true,
		SetGID:       true,
		HandleIno:    53,
		SessionID:    "session",
		SessionToken: "token",
	}
	wire := downgradeRequestWire(t, encodeRequestForTest(t, &want), requestWireLegacyVersion)
	got, err := decodeRequestForTest(wire)
	if err != nil {
		t.Fatalf("decode legacy v2 request: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy request mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestRequestDecoderRejectsV3AtimeFlagOnLegacyV2(t *testing.T) {
	req := Request{
		Op: OpSetattr, Path: "scope/file",
		AtimeMs: 1700000000123, SetATime: true,
	}
	wire := downgradeRequestWire(t, encodeRequestForTest(t, &req), requestWireLegacyVersion)
	if _, err := decodeRequestForTest(wire); !errors.Is(err, errMalformedRequest) {
		t.Fatalf("legacy v2 atime flag error=%v want errMalformedRequest", err)
	}
}

// A v3 peer cannot express a chflags setattr: the SetFlags bit is unknown at
// that version, so a frame claiming it is malformed rather than silently
// decoded as a flag-less setattr that would drop the client's intent.
func TestRequestDecoderRejectsV4FlagsIntentOnOlderVersions(t *testing.T) {
	req := Request{Op: OpSetattr, Path: "scope/file", Flags: 0x2, SetFlags: true}
	wire := encodeRequestForTest(t, &req)
	for _, version := range []uint8{requestWireLegacyVersion, requestWireAtimeVersion} {
		older := downgradeRequestWire(t, wire, version)
		if _, err := decodeRequestForTest(older); !errors.Is(err, errMalformedRequest) {
			t.Fatalf("v%d chflags intent error=%v want errMalformedRequest", version, err)
		}
	}
}

// An older peer's frame still decodes exactly as that peer wrote it: the
// appended scalars read as their zero values, never as bytes stolen from the
// next field.
func TestRequestDecoderReadsOlderVersionsWithoutAppendedScalars(t *testing.T) {
	want := Request{
		Op: OpSetattr, Path: "scope/file", Mode: 0o644, SetMode: true,
		AtimeMs: 1700000000123, SetATime: true, HandleIno: 7,
	}
	wire := downgradeRequestWire(t, encodeRequestForTest(t, &want), requestWireAtimeVersion)
	got, err := decodeRequestForTest(wire)
	if err != nil {
		t.Fatalf("decode v3 request: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v3 request mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestRequestCodecAllowsMaxWriteAndRejectsAggregateOverflow(t *testing.T) {
	data := make([]byte, MaxWriteBytes)
	if err := newRequestEncoder(io.Discard).Encode(&Request{
		Op: OpWrite, Path: "file", Data: data,
	}); err != nil {
		t.Fatalf("exact MaxWriteBytes request was rejected: %v", err)
	}

	// Reuse one bounded string across all metadata fields: no individual
	// field is excessive, but together with the legitimate 64 MiB write the
	// aggregate frame exceeds its independent ceiling.
	text := strings.Repeat("x", maxRequestTextBytes)
	var dst bytes.Buffer
	err := newRequestEncoder(&dst).Encode(&Request{
		Op: OpWrite, Data: data,
		Path: text, NewPath: text, Target: text, Owner: text,
		SessionID: text, SessionToken: text, CheckoutPath: text,
		CheckoutEpoch: text, XattrName: text,
	})
	if !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("aggregate overflow error = %v, want errRequestTooLarge", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("aggregate-overflow encoder wrote %d bytes before rejecting", dst.Len())
	}
}

func TestRequestEncoderBoundsDelegationPreparePathsBeforeWriting(t *testing.T) {
	paths := make([]string, MaxPrepareOpenPaths+1)
	for i := range paths {
		paths[i] = "scope/file"
	}
	var dst bytes.Buffer
	err := newRequestEncoder(&dst).Encode(&Request{
		Op: OpDelegationPrepareRelease, Path: "scope",
		CheckoutEpoch: "epoch", OpenPaths: paths,
	})
	if !errors.Is(err, errMalformedRequest) {
		t.Fatalf("oversize open-path list error = %v, want errMalformedRequest", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("oversize open-path encoder wrote %d bytes before rejecting", dst.Len())
	}

	dst.Reset()
	err = newRequestEncoder(&dst).Encode(&Request{
		Op: OpDelegationPrepareRelease, Path: "scope",
		CheckoutEpoch: "epoch",
		OpenPaths:     []string{strings.Repeat("p", MaxPathBytes+1)},
	})
	if !errors.Is(err, errMalformedRequest) {
		t.Fatalf("oversize individual open path error = %v, want errMalformedRequest", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("oversize individual open path wrote %d bytes before rejecting", dst.Len())
	}
}

func requestDynamicOffset(t *testing.T, wire []byte) int {
	t.Helper()
	// Skip the outer frame header and every fixed-width body field through
	// AckPos. This mirrors the PFRQ2 field order.
	const fixedBodyBytes = 4 + 1 + 1 + 4 +
		8 + 8 + 4 + 8 + 8 + 4 + 4 + 8 +
		8 + 8 + 8 + 1 +
		8 + 8 + 8 +
		8 + 4 + 1 + 8 + 8
	off := 4 + fixedBodyBytes
	if off > len(wire) {
		t.Fatalf("short encoded request: %d bytes", len(wire))
	}
	return off
}

func skipLengthPrefixed(t *testing.T, wire []byte, off int) int {
	t.Helper()
	if off+4 > len(wire) {
		t.Fatalf("missing length at offset %d", off)
	}
	n := int(binary.BigEndian.Uint32(wire[off : off+4]))
	off += 4
	if n > len(wire)-off {
		t.Fatalf("field length %d exceeds %d remaining test bytes", n, len(wire)-off)
	}
	return off + n
}

func TestRequestDecoderRejectsHostileAnnouncedLengthBeforeAllocation(t *testing.T) {
	wire := encodeRequestForTest(t, &Request{Op: OpGetattr})
	off := requestDynamicOffset(t, wire)
	// Nine text fields precede Data.
	for range 9 {
		off = skipLengthPrefixed(t, wire, off)
	}
	binary.BigEndian.PutUint32(wire[off:off+4], ^uint32(0))

	if _, err := decodeRequestForTest(wire); !errors.Is(err, errMalformedRequest) {
		t.Fatalf("hostile inner length error = %v, want errMalformedRequest", err)
	}
}

func TestRequestDecoderRejectsOversizeFrameBeforeReadingBody(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxRequestBytes+1)
	if _, err := decodeRequestForTest(header[:]); !errors.Is(err, errRequestTooLarge) {
		t.Fatalf("oversize frame error = %v, want errRequestTooLarge", err)
	}
}

func TestRequestDecoderRejectsExcessiveCollectionBeforeAllocation(t *testing.T) {
	base := encodeRequestForTest(t, &Request{Op: OpGetattr})
	off := requestDynamicOffset(t, base)
	// Nine text fields and three byte fields precede OrphanInos.
	for range 12 {
		off = skipLengthPrefixed(t, base, off)
	}
	// The empty request has five consecutive zero counts at this point:
	// OrphanInos, OpenInos, OpenPaths, Records, and WBScopes.
	tests := []struct {
		name string
		max  uint32
	}{
		{"orphan inos", maxRequestCollectionItems},
		{"open inos", maxRequestCollectionItems},
		{"open paths", MaxPrepareOpenPaths},
		{"records", MaxBatchRecords},
		{"write-back scopes", maxRequestCollectionItems},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := append([]byte(nil), base...)
			binary.BigEndian.PutUint32(wire[off+4*i:off+4*i+4], tt.max+1)
			if _, err := decodeRequestForTest(wire); !errors.Is(err, errMalformedRequest) {
				t.Fatalf("excessive collection error = %v, want errMalformedRequest", err)
			}
		})
	}
}

func TestSubscribeAckAfterStreamTeardownIsSafe(t *testing.T) {
	_, addr, stop := serveStoppable(t)
	cli, err := Dial(addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	stream, ack, err := cli.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	var pos uint64
	select {
	case bootstrap := <-stream:
		pos = bootstrap.Pos
	case <-time.After(2 * time.Second):
		t.Fatal("subscribe bootstrap did not arrive")
	}
	stop()
	select {
	case _, open := <-stream:
		if open {
			for range stream {
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscribe stream did not tear down")
	}

	// The invalidation consumer may finish applying a batch just after the
	// reader observes teardown. That late ack is a no-op, not a nil-conn
	// panic or race with reset.
	ack(pos)
}
