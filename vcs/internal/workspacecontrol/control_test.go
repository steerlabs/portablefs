package workspacecontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/encoding/protowire"
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
	request := proto.Clone(s).(*pb.Suspension)
	request.Roster = nil
	loss := []*pb.Loss{{Sequence: 1, AcceptedEntries: 1, AcceptedBytes: 4096, Reason: "accepted tail unprovable"}}
	token := &pb.ResumeToken{Suspension: s, WakeNonce: fixtureID(8)}
	status := &pb.MountStatus{Mount: fixtureMount(), State: "terminal", Reason: "session ended; reopen required", Loss: loss, Cleanup: "retained"}
	bodies := map[string]*pb.Envelope{
		"hello": {Body: &pb.Envelope_Hello{Hello: h}}, "hello_ack": {Body: &pb.Envelope_HelloAck{HelloAck: guest}},
		"suspend":      {Body: &pb.Envelope_Suspend{Suspend: request}},
		"suspend_ack":  {Body: &pb.Envelope_SuspendAck{SuspendAck: &pb.SuspendAck{Suspension: s, Mounts: []*pb.MountCold{{Mount: fixtureMount(), Loss: loss}}}}},
		"resume":       {Body: &pb.Envelope_Resume{Resume: token}},
		"resume_ack":   {Body: &pb.Envelope_ResumeAck{ResumeAck: &pb.ResumeAck{Token: token, Mounts: []*pb.MountStatus{status}}}},
		"status":       {Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}},
		"status_reply": {Body: &pb.Envelope_StatusReply{StatusReply: &pb.StatusReply{BootId: s.BootId, HostServiceId: s.HostServiceId, GuestServiceId: s.GuestServiceId, Generation: 1, State: "running", Mounts: []*pb.MountStatus{status}}}},
		"provision":    {Body: &pb.Envelope_Provision{Provision: &pb.Provision{Mount: fixtureMount(), AuthorityEndpoint: "authority.example:7443", CaCertificate: []byte("public CA"), ClientCertificate: []byte("public certificate"), Capability: []byte("signed capability"), PublicKey: []byte("guest public key"), RoutesRevision: bytes.Repeat([]byte{9}, 32)}}},
		"mount":        {Body: &pb.Envelope_Mount{Mount: &pb.MountRequest{Mount: fixtureMount()}}},
		"umount":       {Body: &pb.Envelope_Umount{Umount: &pb.UmountRequest{Mount: fixtureMount()}}},
		"retire_ack":   {Body: &pb.Envelope_RetireAck{RetireAck: &pb.RetireAck{Outcomes: []*pb.MountStatus{{Mount: fixtureMount(), State: "terminal", Reason: "session ended", Cleanup: "complete"}}}}},
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
	var nested []byte
	// The grammar has no recursive messages: a purported >16-level structure
	// already fails at its first impossible nested field. Keep the hostile bytes
	// shared, and exercise the scanner's depth guard directly as well.
	for i := 0; i < 18; i++ {
		nested = protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), nested)
	}
	repeated := []byte{8, 8, 16, 1}
	body := []byte{}
	for i := 0; i < 129; i++ {
		body = append(body, 0x2a, 0)
	}
	repeated = protowire.AppendBytes(protowire.AppendTag(repeated, 12, protowire.BytesType), body)

	return map[string][]byte{
		"unequal_version":    framed([]byte{8, 9, 16, 1, 0x82, 1, 0}),
		"unknown_body":       framed([]byte{8, 8, 16, 1, 0xb2, 1, 0}),
		"duplicate_version":  framed([]byte{8, 8, 8, 8, 16, 1, 0x82, 1, 0}),
		"multiple_body":      framed(append(append([]byte{}, hello[4:]...), status[8:]...)),
		"nonminimal_varint":  framed([]byte{8, 0x88, 0, 16, 1, 0x82, 1, 0}),
		"explicit_default":   framed(append([]byte{8, 8, 16, 1, 0xaa, 1, 12, 10, 8}, append([]byte("accepted"), 18, 0)...)),
		"unknown_nested":     framed([]byte{8, 8, 16, 1, 0xaa, 1, 7, 0x0a, 1, 'x', 0x18, 1, 0x20, 1}),
		"out_of_order":       framed([]byte{16, 1, 8, 8, 0x82, 1, 0}),
		"wrong_wire_type":    framed([]byte{10, 1, 8, 16, 1, 0x82, 1, 0}),
		"zero_length":        {0, 0, 0, 0},
		"zero_request_id":    framed([]byte{8, 8, 0x82, 1, 0}),
		"invalid_utf8":       framed([]byte{8, 8, 16, 1, 0xaa, 1, 3, 0x0a, 1, 0xff}),
		"excessive_nesting":  framed(protowire.AppendBytes(protowire.AppendTag([]byte{8, 8, 16, 1}, 10, protowire.BytesType), nested)),
		"excessive_repeated": framed(repeated),
		"oversized_length":   {0, 0x10, 0, 1}, "truncated": status[:len(status)-1], "trailing": append(status, 0),
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
		{"duplicate roster", func(e *pb.Envelope) { s := e.GetResume().Suspension; s.Roster = append(s.Roster, s.Roster[0]) }},
		{"zero generation", func(e *pb.Envelope) { e.GetResume().Suspension.Generation = 0 }},
		{"bad nonce", func(e *pb.Envelope) { e.GetResume().Suspension.Nonce = make([]byte, 16) }},
		{"bad mount path", func(e *pb.Envelope) { e.GetResume().Suspension.Roster[0].VolumeId = "../escape" }},
		{"roster bound", func(e *pb.Envelope) { e.GetResume().Suspension.Roster = make([]*pb.MountID, 65) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := fixtures()["resume"]
			test.mutate(e)
			if _, err := Encode(e); err == nil {
				t.Fatal("invalid semantic input")
			}
		})
	}
	p := fixtures()["provision"]
	p.GetProvision().PublicKey = []byte("-----BEGIN PRIVATE KEY-----")
	if err := ProvisionForKey(p.GetProvision(), []byte("guest public key")); err == nil {
		t.Fatal("different guest public identity accepted")
	}
	if _, err := Encode(p); err != nil {
		t.Fatal("substring heuristic retained", err)
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
	if err := Write(zeroWriter{}, e); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})); err == nil {
		t.Fatal("unbounded allocation")
	}
}

func TestReviewWorstCaseRepliesFitMaxFrame(t *testing.T) {
	s := fixtureSuspension()
	s.Roster = nil
	var statuses []*pb.MountStatus
	var cold []*pb.MountCold
	for i := 0; i < MaxMounts; i++ {
		mid := fixtureMount()
		mid.VolumeId = fmt.Sprintf("%03d%s", i, strings.Repeat("v", 125))
		s.Roster = append(s.Roster, mid)
		var loss []*pb.Loss
		for n := 1; n <= MaxLosses; n++ {
			loss = append(loss, &pb.Loss{Sequence: uint64(n), AcceptedEntries: math.MaxUint64, AcceptedBytes: math.MaxUint64, Reason: strings.Repeat("r", MaxReason)})
		}
		statuses = append(statuses, &pb.MountStatus{Mount: mid, State: "terminal", Reason: strings.Repeat("r", MaxReason), Cleanup: "complete", Loss: loss})
		cold = append(cold, &pb.MountCold{Mount: mid, Loss: loss})
	}
	var retired []*pb.MountStatus
	for i := 0; i < MaxRetiredBatch; i++ {
		r := proto.Clone(statuses[i]).(*pb.MountStatus)
		r.Mount.Incarnation = fixtureID(30)
		retired = append(retired, r)
	}
	for name, e := range map[string]*pb.Envelope{
		"status":  {Body: &pb.Envelope_StatusReply{StatusReply: &pb.StatusReply{BootId: s.BootId, HostServiceId: s.HostServiceId, GuestServiceId: s.GuestServiceId, Generation: math.MaxUint64, State: "running", Mounts: statuses, Retired: retired}}},
		"suspend": {Body: &pb.Envelope_SuspendAck{SuspendAck: &pb.SuspendAck{Suspension: s, Mounts: cold}}},
		"resume":  {Body: &pb.Envelope_ResumeAck{ResumeAck: &pb.ResumeAck{Token: &pb.ResumeToken{Suspension: s, WakeNonce: fixtureID(8)}, Mounts: statuses}}},
	} {
		t.Run(name, func(t *testing.T) {
			e.Version = Version
			e.RequestId = math.MaxUint64
			raw, err := Encode(e)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) > MaxFrame+4 {
				t.Fatal("semantic maximum exceeds frame")
			}
			if _, err := Decode(raw); err != nil {
				t.Fatal(err)
			}
		})
	}
	// The review's two-mount 128 x 4096-byte input must fail semantic validation.
	e := fixtures()["status_reply"]
	m := e.GetStatusReply().Mounts[0]
	m.Loss = nil
	for i := 1; i <= 128; i++ {
		m.Loss = append(m.Loss, &pb.Loss{Sequence: uint64(i), Reason: strings.Repeat("r", 4096)})
	}
	if Validate(e) == nil {
		t.Fatal("unencodable semantic input accepted")
	}
}
func TestWorkspaceLossAggregationRetainsCounters(t *testing.T) {
	var raw []*pb.Loss
	for i := 1; i <= 129; i++ {
		raw = append(raw, &pb.Loss{Sequence: uint64(i), AcceptedEntries: 1, AcceptedBytes: math.MaxUint64, Reason: "lost"})
	}
	old, _, err := BoundLoss(raw[:MaxLosses])
	if err != nil {
		t.Fatal(err)
	}
	current, overflow, err := BoundLoss(raw)
	if err != nil || !overflow {
		t.Fatal(err)
	}
	if !RetainsLoss(current, old) || current[MaxLosses-1].AcceptedEntries != 98 || current[MaxLosses-1].AcceptedBytes != math.MaxUint64 {
		t.Fatal("aggregation lost counters")
	}
	if losses(current) != nil {
		t.Fatal("aggregate not representable")
	}
}
func TestWorkspaceStateCombinationsAndPublicIdentity(t *testing.T) {
	for _, mutate := range []func(*pb.StatusReply){
		func(s *pb.StatusReply) { s.State = "arbitrary" },
		func(s *pb.StatusReply) { s.State = "suspended-cold"; s.Mounts[0].State = "ready" },
		func(s *pb.StatusReply) { s.Mounts[0].State = "ready"; s.Mounts[0].Cleanup = "complete" },
		func(s *pb.StatusReply) { s.Mounts[0].Reason = "" },
	} {
		e := fixtures()["status_reply"]
		mutate(e.GetStatusReply())
		if Validate(e) == nil {
			t.Fatal("invalid state combination accepted")
		}
	}
	p := fixtures()["provision"].GetProvision()
	if err := ProvisionForKey(p, p.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := ProvisionForKey(p, []byte("other public key")); err == nil {
		t.Fatal("provision identity mismatch accepted")
	}
	// The schema has no private-key import field; random blob contents do not
	// define key type. Only the locally generated public bytes can match.
	if p.ProtoReflect().Descriptor().Fields().ByName("private_key") != nil {
		t.Fatal("private key import surface")
	}
}

func TestWorkspaceScannerDepthBound(t *testing.T) {
	if err := grammar(nil, new(pb.Envelope).ProtoReflect().Descriptor(), 17); err == nil {
		t.Fatal("depth guard omitted")
	}
}
