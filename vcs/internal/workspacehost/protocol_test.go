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
func TestHostOperationalVersionAndOnlyFiveOperations(t *testing.T) {
	for _, operation := range []string{"start", "status", "stop", "mount", "umount", "shell", "exec", "pause", "resume", "identity", "vm-list", "ssh-config"} {
		t.Run(operation, func(t *testing.T) {
			r := Request{Version: 1, Operation: operation}
			if operation == "mount" {
				d := publicRequest(t)
				d.Kind = "connection"
				d.Intent = ""
				d.Identity = nil
				r.Document = &d
			}
			if operation == "umount" {
				r.VolumeID = "vol-1"
			}
			err := r.Validate()
			valid := operation == "start" || operation == "status" || operation == "stop" || operation == "mount" || operation == "umount"
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
