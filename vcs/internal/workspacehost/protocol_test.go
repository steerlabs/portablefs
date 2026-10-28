package workspacehost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

func publicRequest(t *testing.T) Document {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "generated-test-CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "workspace-test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := mountlifecycle.AuthorityIdentity("authority.example")
	aid, _ := hex.DecodeString(authority)
	identity := &pb.IdentityReply{Mount: &pb.MountID{AuthorityId: aid, VolumeId: "vol-1", Incarnation: bytes.Repeat([]byte{1}, 16)}, PublicKey: spki, Csr: csr, GuestUuid: bytes.Repeat([]byte{2}, 16), IdentityIncarnation: bytes.Repeat([]byte{3}, 16), RenewalEpoch: 1}
	connection := Connection{Authority: authority, VolumeID: "vol-1", Endpoint: "authority.example:7443", ServerName: "authority.example", CACertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), RoutesRevision: bytes.Repeat([]byte{4}, 32)}
	d, err := NewAuthorizationRequest(connection, "01010101010101010101010101010101", identity)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestHostOperationalVersionAndExactOperations(t *testing.T) {
	for _, operation := range []string{"start", "status", "stop", "mount", "umount", "dismiss", "dismiss-reopen", "shell", "exec", "pause", "resume", "identity", "vm-list", "ssh-config"} {
		t.Run(operation, func(t *testing.T) {
			r := Request{Version: 1, Operation: operation}
			if operation == "mount" {
				d := publicRequest(t)
				d.Kind = "connection"
				d.Intent = ""
				d.Identity = nil
				r.Document = &d
			}
			if operation == "umount" || operation == "dismiss-reopen" {
				r.VolumeID = "vol-1"
			}
			if operation == "dismiss-reopen" {
				r.ReopenID = strings.Repeat("01", 16)
			}
			if operation == "dismiss" {
				r.OutcomeID = "1/01010101010101010101010101010101/vol-1"
			}
			err := r.Validate()
			valid := operation == "start" || operation == "status" || operation == "stop" || operation == "mount" || operation == "umount" || operation == "dismiss" || operation == "dismiss-reopen"
			if (err == nil) != valid {
				t.Fatalf("validation %v", err)
			}
			r.Version = 8
			if r.Validate() == nil {
				t.Fatal("guest protocol confused with host operational version")
			}
		})
	}
	for _, raw := range []string{`{"version":1,"operation":"status","version":1}`, `{"version":1,"operation":"status","secret":"x"}`, `{"version":1,"operation":"status"} {}`, `{"version":1,"operation":null}`} {
		if _, err := DecodeRequest([]byte(raw)); err == nil {
			t.Fatal("malformed request accepted")
		}
	}
}
func TestPublicDocumentExactRequestAndResponseBinding(t *testing.T) {
	d := publicRequest(t)
	identity, _ := d.GuestIdentity()
	p := &pb.Provision{Mount: proto.Clone(identity.Mount).(*pb.MountID), PublicKey: identity.PublicKey, AuthorityEndpoint: d.Connection.Endpoint, ServerName: d.Connection.ServerName, CaCertificate: d.Connection.CACertificate, ClientCertificate: []byte("issuer response validated in guest"), Capability: []byte("generated-test-grant"), RoutesRevision: d.Connection.RoutesRevision}
	response := d
	response.Kind = "authorization"
	var err error
	response.Authorization, err = workspacecontrol.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_Provision{Provision: p}})
	if err != nil {
		t.Fatal(err)
	}
	if err = response.Validate(); err != nil {
		t.Fatal(err)
	}
	if !response.MatchesRequest(d) {
		t.Fatal("valid response not matched")
	}
	for _, field := range []string{"key", "mount", "authority", "route", "endpoint", "intent", "epoch", "scope"} {
		t.Run(field, func(t *testing.T) {
			clone := response
			provision := proto.Clone(p).(*pb.Provision)
			switch field {
			case "key":
				provision.PublicKey = []byte("wrong")
			case "mount":
				provision.Mount.Incarnation = bytes.Repeat([]byte{9}, 16)
			case "authority":
				clone.Connection.Authority = hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
			case "route":
				provision.RoutesRevision = bytes.Repeat([]byte{8}, 32)
			case "endpoint":
				provision.AuthorityEndpoint = "other.example:7443"
			case "intent":
				clone.Intent = "02020202020202020202020202020202"
			case "epoch", "scope":
				other := proto.Clone(identity).(*pb.IdentityReply)
				if field == "epoch" {
					other.RenewalEpoch++
				} else {
					other.IdentityIncarnation = bytes.Repeat([]byte{9}, 16)
				}
				clone.Identity, _ = workspacecontrol.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_IdentityReply{IdentityReply: other}})
			}
			clone.Authorization, _ = workspacecontrol.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_Provision{Provision: provision}})
			if clone.Validate() == nil && clone.MatchesRequest(d) {
				t.Fatal("substituted response matched public request")
			}
		})
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("private key exported")
	}
	for _, variant := range [][]byte{bytes.Replace(raw, []byte(`"kind":"request"`), []byte(`"kind":"request","privateKey":"no"`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1)} {
		if _, err := DecodeDocument(variant); err == nil {
			t.Fatal("non-exact document accepted")
		}
	}
}
func TestDocumentRejectsHostLoopbackAndInvalidCSR(t *testing.T) {
	for _, endpoint := range []string{"localhost:7443", "127.0.0.1:7443", "[::1]:7443", "0.0.0.0:7443", "authority.example:0", "https://authority.example:7443"} {
		d := publicRequest(t)
		d.Connection.Endpoint = endpoint
		if d.Validate() == nil {
			t.Fatalf("endpoint accepted: %s", endpoint)
		}
	}
	d := publicRequest(t)
	identity, _ := d.GuestIdentity()
	identity.Csr[len(identity.Csr)-1] ^= 1
	d.Identity, _ = workspacecontrol.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_IdentityReply{IdentityReply: identity}})
	if d.Validate() == nil {
		t.Fatal("invalid CSR signature accepted")
	}
}

func TestLifecycleVersionHasAnIndependentExactNamespace(t *testing.T) {
	for _, operation := range []string{"identity", "inventory", "quiesce"} {
		raw := []byte(`{"lifecycleVersion":1,"operation":"` + operation + `"}`)
		if _, err := DecodeLifecycle(raw); err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequest(raw); err == nil {
			t.Fatal("lifecycle frame admitted as an operational verb")
		}
	}
	for _, raw := range []string{`{"lifecycleVersion":8,"operation":"identity"}`, `{"lifecycleVersion":1,"operation":"start"}`, `{"lifecycleVersion":1,"operation":"quiesce","force":true}`, `{"version":1,"operation":"status"}`} {
		if _, err := DecodeLifecycle([]byte(raw)); err == nil {
			t.Fatal("invalid lifecycle frame accepted")
		}
	}
}

func TestExactOutcomeIdentityAndDismissGrammar(t *testing.T) {
	const id = "17/01010101010101010101010101010101/vol-1"
	for _, tc := range []struct {
		id    string
		valid bool
	}{
		{id, true}, {"1/01010101010101010101010101010101/-", true},
		{"", false}, {"all", false}, {"17", false}, {"0/01010101010101010101010101010101/vol-1", false},
		{"017/01010101010101010101010101010101/vol-1", false}, {"17/00000000000000000000000000000000/vol-1", false},
		{"17/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/vol-1", false}, {id + "/extra", false}, {"17/01010101010101010101010101010101/..", false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			if ValidOutcomeID(tc.id) != tc.valid {
				t.Fatal("identity validation differs")
			}
			raw, _ := json.Marshal(Request{Version: 1, Operation: "dismiss", OutcomeID: tc.id})
			if _, err := DecodeRequest(raw); (err == nil) != tc.valid {
				t.Fatal(err)
			}
		})
	}
	for _, request := range []Request{
		{Version: 1, Operation: "status", OutcomeID: id},
		{Version: 1, Operation: "stop", OutcomeID: id},
		{Version: 1, Operation: "dismiss", OutcomeID: id, Force: true},
		{Version: 1, Operation: "dismiss", OutcomeID: id, VolumeID: "vol-1"},
	} {
		if request.Validate() == nil {
			t.Fatal("implicit or non-exact acknowledgement accepted", request)
		}
	}
	reply := Reply{Version: 1, State: "stopped", Volumes: []Volume{}, Outcomes: []Outcome{{ID: id, PreviousWriteOutcomeUnknown: true}}}
	raw, _ := json.Marshal(reply)
	if _, err := DecodeReply(raw); err != nil {
		t.Fatal(err)
	}
	reply.Outcomes = append(reply.Outcomes, reply.Outcomes[0])
	raw, _ = json.Marshal(reply)
	if _, err := DecodeReply(raw); err == nil {
		t.Fatal("duplicate outcome identity accepted")
	}
}

func TestReopenDismissalNamesOneIncarnationWithoutChangingPublicVerbs(t *testing.T) {
	id := strings.Repeat("01", 16)
	cases := []struct {
		name    string
		request Request
		valid   bool
	}{
		{"exact", Request{Version: 1, Operation: "dismiss-reopen", VolumeID: "vol-1", ReopenID: id}, true},
		{"missing-id", Request{Version: 1, Operation: "dismiss-reopen", VolumeID: "vol-1"}, false},
		{"missing-volume", Request{Version: 1, Operation: "dismiss-reopen", ReopenID: id}, false},
		{"zero-id", Request{Version: 1, Operation: "dismiss-reopen", VolumeID: "vol-1", ReopenID: strings.Repeat("0", 32)}, false},
		{"status-is-read-only", Request{Version: 1, Operation: "status", ReopenID: id}, false},
		{"outcome-is-separate", Request{Version: 1, Operation: "dismiss", OutcomeID: "1/" + id + "/vol-1", ReopenID: id}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.request)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeRequest(raw)
			if (err == nil) != tc.valid {
				t.Fatalf("validation: %v", err)
			}
		})
	}
	reply := Reply{Version: 1, State: "running", Volumes: []Volume{{VolumeID: "vol-1", Path: "/workspaces/vol-1", State: "ready", Message: "Reconnect your editor and reopen this folder.", ReopenID: id}}}
	raw, _ := json.Marshal(reply)
	if _, err := DecodeReply(raw); err != nil {
		t.Fatal(err)
	}
	reply.Volumes[0].State = "pending"
	raw, _ = json.Marshal(reply)
	if _, err := DecodeReply(raw); err == nil {
		t.Fatal("pending mount exposed a ready-only dismissal")
	}
}
