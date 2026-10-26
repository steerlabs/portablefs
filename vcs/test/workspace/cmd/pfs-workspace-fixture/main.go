// Command pfs-workspace-fixture owns only disposable native-test PKI and
// protobuf encoding. It never imports or exports a guest private key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"github.com/steerlabs/portablefs/vcs/internal/workspacehost"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "workspace test fixture:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("fixture operation required")
	}
	switch args[0] {
	case "document-connection":
		if len(args) != 4 {
			return errors.New("document-connection GENERATED_TEST_PKI ENDPOINT VOLUME")
		}
		ca, err := os.ReadFile(filepath.Join(args[1], "server-ca.pem"))
		if err != nil {
			return err
		}
		authority, err := mountlifecycle.AuthorityIdentity("authority.portablefs.test")
		if err != nil {
			return err
		}
		revision := localroutes.RuleSet{}.Revision()
		return json.NewEncoder(os.Stdout).Encode(workspacehost.Document{Version: 1, Kind: "connection", Connection: workspacehost.Connection{Authority: authority, VolumeID: args[3], Endpoint: args[2], ServerName: "authority.portablefs.test", CACertificate: ca, RoutesRevision: revision[:]}})
	case "document-authorize":
		if len(args) != 3 {
			return errors.New("document-authorize GENERATED_TEST_PKI PUBLIC_REQUEST_BASE64")
		}
		raw, err := base64.StdEncoding.DecodeString(args[2])
		if err != nil {
			return err
		}
		document, err := workspacehost.DecodeDocument(raw)
		if err != nil {
			return err
		}
		identity, err := document.GuestIdentity()
		if err != nil {
			return err
		}
		body, err := proto.Marshal(identity)
		if err != nil {
			return err
		}
		encoded, err := exec.Command(os.Args[0], "provision", args[1], document.Connection.Endpoint, base64.StdEncoding.EncodeToString(body)).Output()
		if err != nil {
			return errors.New("generated test issuer failed")
		}
		material := new(pb.Provision)
		if err = decode(strings.TrimSpace(string(encoded)), material); err != nil {
			return err
		}
		response, err := document.Authorize(material)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(response)
	case "setup":
		if len(args) != 3 {
			return errors.New("setup DIRECTORY VOLUME")
		}
		return setup(args[1], args[2])
	case "provision", "provision-short":
		if len(args) != 4 {
			return errors.New("provision DIRECTORY ENDPOINT IDENTITY_BASE64")
		}
		lifetime := time.Hour
		if args[0] == "provision-short" {
			lifetime = 25 * time.Second
		}
		return provisionGuest(args[1], args[2], args[3], lifetime)
	case "identity-request":
		if len(args) != 2 {
			return errors.New("identity-request VOLUME")
		}
		return printProto(&pb.IdentityRequest{AuthorityId: authorityID(), VolumeId: args[1]})
	case "decode-identity":
		if len(args) != 2 {
			return errors.New("decode-identity BASE64")
		}
		v := new(pb.IdentityReply)
		if err := decode(args[1], v); err != nil {
			return err
		}
		mount, err := proto.Marshal(v.Mount)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"mount": base64.StdEncoding.EncodeToString(mount), "public_key": base64.StdEncoding.EncodeToString(v.PublicKey), "guest_uuid": base64.StdEncoding.EncodeToString(v.GuestUuid), "identity_incarnation": base64.StdEncoding.EncodeToString(v.IdentityIncarnation)})
	case "decode-status":
		if len(args) != 2 {
			return errors.New("decode-status BASE64")
		}
		v := new(pb.StatusReply)
		if err := decode(args[1], v); err != nil {
			return err
		}
		raw, err := protojson.Marshal(v)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(raw)
		return err
	}
	return errors.New("unknown fixture operation")
}
func authorityID() []byte {
	v := make([]byte, 32)
	for n := range v {
		v[n] = 4
	}
	return v
}
func decode(raw string, v proto.Message) error {
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, v)
}
func printProto(v proto.Message) error {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(raw))
	return nil
}
func write(dir, name, kind string, der []byte, mode os.FileMode) error {
	return os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), mode)
}
func key(dir, name string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, errors.New("invalid generated test key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	v, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("unexpected test key type")
	}
	return v, nil
}
func cert(dir, name string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, errors.New("invalid test certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}
func issue(name string, pub ed25519.PublicKey, parent *x509.Certificate, signer ed25519.PrivateKey, ca, client bool) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		t.KeyUsage |= x509.KeyUsageCertSign
	} else if client {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		t.DNSNames = []string{name}
	}
	if parent == nil {
		parent = t
	}
	return x509.CreateCertificate(rand.Reader, t, parent, pub, signer)
}
func newKey(dir, name string) (ed25519.PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return k, write(dir, name, "PRIVATE KEY", der, 0600)
}
func setup(dir, volume string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for _, name := range []string{"server-ca", "client-ca"} {
		k, err := newKey(dir, name+".key")
		if err != nil {
			return err
		}
		der, err := issue(name, k.Public().(ed25519.PublicKey), nil, k, true, false)
		if err != nil {
			return err
		}
		if err = write(dir, name+".pem", "CERTIFICATE", der, 0644); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name, ca string
		client   bool
	}{{"server", "server-ca", false}, {"peer", "client-ca", true}} {
		k, err := newKey(dir, item.name+".key")
		if err != nil {
			return err
		}
		signer, err := key(dir, item.ca+".key")
		if err != nil {
			return err
		}
		parent, err := cert(dir, item.ca+".pem")
		if err != nil {
			return err
		}
		name := item.name
		if !item.client {
			name = "authority.portablefs.test"
		}
		der, err := issue(name, k.Public().(ed25519.PublicKey), parent, signer, false, item.client)
		if err != nil {
			return err
		}
		if err = write(dir, item.name+".pem", "CERTIFICATE", der, 0644); err != nil {
			return err
		}
	}
	k, err := newKey(dir, "capability.key")
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		return err
	}
	if err = write(dir, "capability-public.pem", "PUBLIC KEY", der, 0644); err != nil {
		return err
	}
	peer, err := cert(dir, "peer.pem")
	if err != nil {
		return err
	}
	token, err := grant(k, volume, peer.RawSubjectPublicKeyInfo, time.Hour)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "peer.token"), token, 0600)
}
func grant(k ed25519.PrivateKey, volume string, spki []byte, lifetime time.Duration) ([]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(spki)
	return volumecap.Sign(k, volumecap.Claims{VolumeID: volume, Subject: "native-workspace-test", Access: []string{"read", "write"}, NotBefore: time.Now().Add(-time.Minute).Unix(), Expires: time.Now().Add(lifetime).Unix(), PeerSPKI: base64.RawURLEncoding.EncodeToString(hash[:]), Nonce: hex.EncodeToString(nonce[:])})
}
func provisionGuest(dir, endpoint, identity string, lifetime time.Duration) error {
	v := new(pb.IdentityReply)
	if err := decode(identity, v); err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(v.Csr)
	if err != nil {
		return err
	}
	if err = csr.CheckSignature(); err != nil {
		return err
	}
	pub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("guest CSR key type")
	}
	if string(csr.RawSubjectPublicKeyInfo) != string(v.PublicKey) {
		return errors.New("guest CSR/SPKI mismatch")
	}
	signer, err := key(dir, "client-ca.key")
	if err != nil {
		return err
	}
	parent, err := cert(dir, "client-ca.pem")
	if err != nil {
		return err
	}
	leaf, err := issue("workspace-test-guest", pub, parent, signer, false, true)
	if err != nil {
		return err
	}
	k, err := key(dir, "capability.key")
	if err != nil {
		return err
	}
	token, err := grant(k, v.Mount.VolumeId, v.PublicKey, lifetime)
	if err != nil {
		return err
	}
	ca, err := os.ReadFile(filepath.Join(dir, "server-ca.pem"))
	if err != nil {
		return err
	}
	revision := localroutes.RuleSet{}.Revision()
	return printProto(&pb.Provision{Mount: v.Mount, AuthorityEndpoint: endpoint, CaCertificate: ca, ClientCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), Capability: token, RoutesRevision: revision[:], PublicKey: v.PublicKey, ServerName: "authority.portablefs.test"})
}
