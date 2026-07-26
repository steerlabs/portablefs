package pfslocal

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "pfslocal", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGoldenHelloRequestFrame(t *testing.T) {
	env := &Envelope{RequestID: 1, Body: &Hello{ProtocolMajor: 1, ClientName: "swift", ClientVersion: "1.0"}}
	got, err := EncodeFrame(env)
	if err != nil {
		t.Fatal(err)
	}
	if want := readGolden(t, "hello_request.hex"); !bytes.Equal(got, want) {
		t.Fatalf("hello request frame\n got %x\nwant %x", got, want)
	}
	dec, err := ReadFrame(bytes.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	hello, ok := dec.Body.(*Hello)
	if !ok || dec.RequestID != 1 || hello.ProtocolMajor != 1 || hello.ClientName != "swift" || hello.ClientVersion != "1.0" {
		t.Fatalf("decoded hello = %#v %#v", dec, dec.Body)
	}
}

func TestGoldenHelloReplyFrame(t *testing.T) {
	env := &Envelope{RequestID: 1, Body: &HelloReply{ProtocolMajor: 1, DaemonVersion: "portablefsd-test"}}
	got, err := EncodeFrame(env)
	if err != nil {
		t.Fatal(err)
	}
	if want := readGolden(t, "hello_reply.hex"); !bytes.Equal(got, want) {
		t.Fatalf("hello reply frame\n got %x\nwant %x", got, want)
	}
	dec, err := ReadFrame(bytes.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	rep, ok := dec.Body.(*HelloReply)
	if !ok || dec.RequestID != 1 || rep.ProtocolMajor != 1 || rep.DaemonVersion != "portablefsd-test" {
		t.Fatalf("decoded reply = %#v %#v", dec, dec.Body)
	}
}

func TestFramingRejectsOversized(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(MaxFrameBytes+1))
	if _, err := ReadFrame(bytes.NewReader(hdr[:])); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame oversized err=%v", err)
	}
}

func TestStreamMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Envelope{RequestID: 2, Body: &OpenReply{Handle: 99}}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, &Envelope{RequestID: 1, Body: &CloseReply{}}); err != nil {
		t.Fatal(err)
	}
	first, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != 2 || second.RequestID != 1 {
		t.Fatalf("stream order ids = %d, %d", first.RequestID, second.RequestID)
	}
}
