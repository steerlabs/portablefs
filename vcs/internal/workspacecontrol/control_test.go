package workspacecontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

var update = flag.Bool("update-workspace-goldens", false, "regenerate paired workspace control fixtures")

func fixtureID(n byte) []byte { return bytes.Repeat([]byte{n}, 16) }
func fixtureMount() *pb.MountID {
	return &pb.MountID{AuthorityId: bytes.Repeat([]byte{1}, 32), VolumeId: "example", Incarnation: fixtureID(2)}
}
func fixtureHello() *pb.Hello {
	return &pb.Hello{Release: &pb.Release{AppVersion: "0.0.0-stage1a", Commit: strings.Repeat("a", 40), ImageDigest: bytes.Repeat([]byte{3}, 32), AuthorityMajor: 8}, BootId: fixtureID(4), HostServiceId: fixtureID(5)}
}
func fixtureSuspension() *pb.Suspension {
	return &pb.Suspension{BootId: fixtureID(4), HostServiceId: fixtureID(5), GuestServiceId: fixtureID(6), Generation: 1, Roster: []*pb.MountID{fixtureMount()}, Nonce: fixtureID(7)}
}
func fixtures() map[string]*pb.Envelope {
	h := fixtureHello()
	guest := proto.Clone(h).(*pb.Hello)
	guest.GuestServiceId = fixtureID(6)
	s := fixtureSuspension()
	loss := []*pb.Loss{{Sequence: 1, AcceptedEntries: 1, AcceptedBytes: 4096, Reason: "accepted tail unprovable"}}
	token := &pb.ResumeToken{Suspension: s, WakeNonce: fixtureID(8)}
	status := &pb.MountStatus{Mount: fixtureMount(), State: "terminal", Reason: "session ended; reopen required", Loss: loss, Cleanup: "retained"}
	bodies := map[string]*pb.Envelope{
		"hello": {Body: &pb.Envelope_Hello{Hello: h}}, "hello_ack": {Body: &pb.Envelope_HelloAck{HelloAck: guest}},
		"suspend":      {Body: &pb.Envelope_Suspend{Suspend: s}},
		"suspend_ack":  {Body: &pb.Envelope_SuspendAck{SuspendAck: &pb.SuspendAck{Suspension: s, Mounts: []*pb.MountCold{{Mount: fixtureMount(), ColdComplete: true, Loss: loss}}}}},
		"resume":       {Body: &pb.Envelope_Resume{Resume: token}},
		"resume_ack":   {Body: &pb.Envelope_ResumeAck{ResumeAck: &pb.ResumeAck{Token: token, Mounts: []*pb.MountStatus{status}}}},
		"status":       {Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}},
		"status_reply": {Body: &pb.Envelope_StatusReply{StatusReply: &pb.StatusReply{BootId: s.BootId, HostServiceId: s.HostServiceId, GuestServiceId: s.GuestServiceId, Generation: 1, State: "running", Mounts: []*pb.MountStatus{status}}}},
		"provision":    {Body: &pb.Envelope_Provision{Provision: &pb.Provision{Mount: fixtureMount(), AuthorityEndpoint: "authority.example:7443", CaCertificate: []byte("public CA"), ClientCertificate: []byte("public certificate"), Capability: []byte("signed capability"), PublicKey: []byte("guest public key"), RoutesRevision: bytes.Repeat([]byte{9}, 32)}}},
		"mount":        {Body: &pb.Envelope_Mount{Mount: &pb.MountRequest{Mount: fixtureMount()}}},
		"umount":       {Body: &pb.Envelope_Umount{Umount: &pb.UmountRequest{Mount: fixtureMount()}}},
		"result":       {Body: &pb.Envelope_Result{Result: &pb.Result{Code: "unavailable", Reason: "mount integration pending"}}},
	}
	for _, e := range bodies {
		e.Version = 8
		e.RequestId = 1
	}
	return bodies
}
func framed(payload []byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	return append(out, payload...)
}
func invalidFixtures() map[string][]byte {
	status, _ := Encode(fixtures()["status"])
	hello, _ := Encode(fixtures()["hello"])
	return map[string][]byte{
		"unequal_version":   framed([]byte{8, 9, 16, 1, 0x82, 1, 0}),
		"unknown_body":      framed([]byte{8, 8, 16, 1, 0xb2, 1, 0}),
		"duplicate_version": framed([]byte{8, 8, 8, 8, 16, 1, 0x82, 1, 0}),
		"multiple_body":     framed(append(append([]byte{}, hello[4:]...), status[8:]...)),
		"nonminimal_varint": framed([]byte{8, 0x88, 0, 16, 1, 0x82, 1, 0}),
		"explicit_default":  framed(append([]byte{8, 8, 16, 1, 0xaa, 1, 12, 10, 8}, append([]byte("accepted"), 18, 0)...)),
		"unknown_nested":    framed([]byte{8, 8, 16, 1, 0xaa, 1, 7, 0x0a, 1, 'x', 0x18, 1, 0x20, 1}),
		"oversized_length":  {0, 0x10, 0, 1}, "truncated": status[:len(status)-1], "trailing": append(status, 0),
	}
}
func golden(t *testing.T, name string, raw []byte) {
	t.Helper()
	shared := filepath.Join("../../../proto/workspace/v8/testdata", name+".hex")
	swift := filepath.Join("../../../swift/PortableFSKit/Tests/PortableFSWorkspaceCoreTests/Goldens", name+".hex")
	if *update {
		for _, path := range []string{shared, swift} {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	a, err := os.ReadFile(shared)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(swift)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("Go/Swift fixture differs")
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(a)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("fixture %s differs", name)
	}
}
func TestWorkspaceGoldenFrames(t *testing.T) {
	for name, e := range fixtures() {
		t.Run(name, func(t *testing.T) {
			raw, err := Encode(e)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, name, raw)
			got, err := Decode(raw)
			if err != nil || !proto.Equal(e, got) {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
	for name, raw := range invalidFixtures() {
		t.Run(name, func(t *testing.T) {
			golden(t, name+".invalid", raw)
			if _, err := Decode(raw); err == nil {
				t.Fatal("accepted malformed frame")
			}
		})
	}
}
func TestWorkspaceSchemaFreshness(t *testing.T) {
	raw, err := os.ReadFile("../../../proto/workspace/v8/control.proto")
	if err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(raw))
	if sum != SchemaSHA256 {
		t.Fatal("regenerate workspace bindings")
	}
	for _, tc := range []struct{ path, want string }{
		{"../workspacepb/control.pb.go", GoBindingSHA256},
		{"../../../swift/PortableFSKit/Sources/PortableFSWorkspaceCore/Generated/proto/workspace/v8/control.pb.swift", SwiftBindingSHA256},
		{"../../../swift/PortableFSKit/Sources/PortableFSWorkspaceCore/Generated/WorkspaceWireSchema.swift", SwiftWireSchemaSHA256},
	} {
		raw, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != tc.want {
			t.Fatalf("stale paired binding: %s", tc.path)
		}
	}
}
func TestWorkspaceExactPairing(t *testing.T) {
	for _, field := range []string{"version", "commit", "image", "authority", "boot", "host", "guest"} {
		t.Run(field, func(t *testing.T) {
			h := fixtureHello()
			g := proto.Clone(h).(*pb.Hello)
			g.GuestServiceId = fixtureID(6)
			if err := Pair(h, g); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "version":
				g.Release.AppVersion = "other"
			case "commit":
				g.Release.Commit = strings.Repeat("b", 40)
			case "image":
				g.Release.ImageDigest[0]++
			case "authority":
				g.Release.AuthorityMajor = 7
			case "boot":
				g.BootId = fixtureID(10)
			case "host":
				g.HostServiceId = fixtureID(10)
			case "guest":
				g.GuestServiceId = nil
			}
			if err := Pair(h, g); err == nil {
				t.Fatal("accepted unequal pairing")
			}
		})
	}
}
func TestWorkspaceSemanticRefusals(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*pb.Envelope)
	}{
		{"duplicate roster", func(e *pb.Envelope) { s := e.GetSuspend(); s.Roster = append(s.Roster, s.Roster[0]) }},
		{"zero generation", func(e *pb.Envelope) { e.GetSuspend().Generation = 0 }},
		{"bad nonce", func(e *pb.Envelope) { e.GetSuspend().Nonce = make([]byte, 16) }},
		{"bad mount path", func(e *pb.Envelope) { e.GetSuspend().Roster[0].VolumeId = "../escape" }},
		{"roster bound", func(e *pb.Envelope) { e.GetSuspend().Roster = make([]*pb.MountID, 65) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := fixtures()["suspend"]
			test.mutate(e)
			if _, err := Encode(e); err == nil {
				t.Fatal("invalid semantic input")
			}
		})
	}
	p := fixtures()["provision"]
	p.GetProvision().PublicKey = []byte("-----BEGIN PRIVATE KEY-----")
	if _, err := Encode(p); err == nil {
		t.Fatal("private-key import accepted")
	}
}

type chunkWriter struct{ bytes.Buffer }

func (w *chunkWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
func TestWorkspaceStreamFraming(t *testing.T) {
	var w chunkWriter
	e := fixtures()["suspend"]
	if err := Write(&w, e); err != nil {
		t.Fatal(err)
	}
	if err := Write(&w, fixtures()["status"]); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(&w); err != nil || !proto.Equal(got, e) {
		t.Fatalf("short writes: %v", err)
	}
	if _, err := Read(&w); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(&w); err == nil {
		t.Fatal("missing EOF")
	}
	if err := Write(zeroWriter{}, e); err != io.ErrShortWrite {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})); err == nil {
		t.Fatal("unbounded allocation")
	}
}
