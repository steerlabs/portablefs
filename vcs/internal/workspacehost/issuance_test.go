package workspacehost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func issuanceCA(t *testing.T) *controlplane.CertificateAuthority {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "generated workspace issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := controlplane.ParseCertificateAuthority(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}
func TestDocumentRealStandaloneCSRSigningAndGuestProvision(t *testing.T) {
	ca := issuanceCA(t)
	s, err := workspacemount.Open(filepath.Join(t.TempDir(), "generated-identities"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	authority, _ := mountlifecycle.AuthorityIdentity("authority.example")
	aid, _ := hex.DecodeString(authority)
	identity, err := s.EnsureIdentity(&pb.IdentityRequest{AuthorityId: aid, VolumeId: "standalone"})
	if err != nil {
		t.Fatal(err)
	}
	c := Connection{Authority: authority, VolumeID: "standalone", Endpoint: "authority.example:7443", ServerName: "authority.example", CACertificate: []byte(ca.CertificatePEM), RoutesRevision: bytes.Repeat([]byte{1}, 32)}
	request, err := NewAuthorizationRequest(c, "01010101010101010101010101010101", identity)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, err := ca.SignCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: identity.Csr}), "guest", nil, true, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	peer := sha256.Sum256(identity.PublicKey)
	grant, err := volumecap.Sign(signer, volumecap.Claims{VolumeID: c.VolumeID, Subject: "standalone-operator", Access: []string{"read", "write"}, NotBefore: time.Now().Add(-time.Minute).Unix(), Expires: time.Now().Add(time.Hour).Unix(), PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: "generated-initial-grant"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := request.Authorize(&pb.Provision{Mount: identity.Mount, AuthorityEndpoint: c.Endpoint, ServerName: c.ServerName, CaCertificate: c.CACertificate, RoutesRevision: c.RoutesRevision, ClientCertificate: []byte(leaf), Capability: grant, PublicKey: identity.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	p, err := response.Provision()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AcceptProvision(t.Context(), p, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	authorizer := &volumecap.Authorizer{PublicKey: signer.Public().(ed25519.PublicKey), MaxLifetime: 2 * time.Hour, MaxRetainedNonces: 64}
	if _, err = authorizer.Verify(c.VolumeID, p.Capability, peer); err != nil {
		t.Fatal(err)
	}
	if _, err = authorizer.Verify(c.VolumeID, p.Capability, peer); err == nil {
		t.Fatal("initial grant reused")
	}
	wrong := sha256.Sum256([]byte("wrong generated guest"))
	if _, err = authorizer.Verify(c.VolumeID, p.Capability, wrong); err == nil {
		t.Fatal("wrong guest key accepted")
	}
	corrupt := bytes.Clone(p.Capability)
	corrupt[len(corrupt)-1] ^= 1
	if _, err = authorizer.Verify(c.VolumeID, corrupt, peer); err == nil {
		t.Fatal("wrong grant accepted")
	}
}
func TestDocumentRealHostedManagerScopeEpochAndRenewalOwnership(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	_, planKey, _ := ed25519.GenerateKey(rand.Reader)
	_, capKey, _ := ed25519.GenerateKey(rand.Reader)
	productPublic, productKey, _ := ed25519.GenerateKey(rand.Reader)
	serverCA, clientCA, enrollmentCA := issuanceCA(t), issuanceCA(t), issuanceCA(t)
	store, err := controlplane.OpenStore(filepath.Join(t.TempDir(), "manager.state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager, err := controlplane.NewManager(controlplane.ManagerConfig{Store: store, PlanPrivateKey: planKey, CapabilityPrivateKey: capKey, ProductIssuers: map[string]ed25519.PublicKey{"workspace-product": productPublic}, AuthorityCA: serverCA, ClientCA: clientCA, EnrollmentCA: enrollmentCA, Now: func() time.Time { return now }, ReleaseID: "workspace-test", PlanLifetime: 10 * time.Minute, GrantLifetime: 2 * time.Minute, EnrollmentLease: 30 * time.Minute, ProductMaxLifetime: 15 * time.Minute, ClientCertLifetime: time.Hour, AuthorityCertLifetime: 12 * time.Hour, ObservedStaleAfter: 2 * time.Minute, ClockSkew: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cell, err := manager.RegisterCell("cell", controlplane.RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.example", AuthorityDNSZone: "cell.example", CapacityBytes: 8 << 30, CapacityInodes: 800000, Pool: controlplane.PoolProduct, LastProjectID: 19999, LastServiceUID: 209999, LastPort: 29999})
	if err != nil {
		t.Fatal(err)
	}
	observe := func(id string, volumes []controlplane.VolumeObservation) {
		t.Helper()
		envelope, e := manager.CellPlan(cell.ID)
		if e != nil {
			t.Fatal(e)
		}
		plan, _, e := cellplan.Verify(planKey.Public().(ed25519.PublicKey), envelope, cell.ID, now, time.Second, 10*time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		cell, e = manager.ObserveCell(id, controlplane.CellObservation{CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: manager.ReleaseIdentity(), AgentReleaseID: "test-agent", HelperReleaseID: "test-helper", ObservedUnix: now.Unix(), ArchiveConfigured: true, Volumes: volumes})
		if e != nil {
			t.Fatal(e)
		}
	}
	observe("admission", nil)
	observe("admission-current", nil)
	volume, err := manager.CreateVolume("volume", controlplane.CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "workspace-product", QuotaBytes: 1 << 30, QuotaInodes: 100000})
	if err != nil {
		t.Fatal(err)
	}
	_, authorityKey, _ := ed25519.GenerateKey(rand.Reader)
	authorityCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "authority"}}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	observation := controlplane.VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID, ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort, Provisioned: true, AuthorityCSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: authorityCSR}))}
	observe("csr", []controlplane.VolumeObservation{observation})
	observation.AuthorityCSRPEM = ""
	observation.AuthorityRunning = true
	observe("running", []controlplane.VolumeObservation{observation})
	volume, err = manager.GetVolume(volume.ID)
	if err != nil || volume.State != controlplane.VolumeReady {
		t.Fatalf("volume not ready: %v %s", err, volume.State)
	}
	guest, err := workspacemount.Open(filepath.Join(t.TempDir(), "generated-identities"))
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	authority, _ := mountlifecycle.AuthorityIdentity(volume.Placement.AuthorityServerName)
	aid, _ := hex.DecodeString(authority)
	identityRequest := &pb.IdentityRequest{AuthorityId: aid, VolumeId: volume.ID}
	identity, err := guest.EnsureIdentity(identityRequest)
	if err != nil {
		t.Fatal(err)
	}
	connection := Connection{Authority: authority, VolumeID: volume.ID, Endpoint: net.JoinHostPort(cell.AuthorityHost, fmt.Sprint(volume.Placement.ListenPort)), ServerName: volume.Placement.AuthorityServerName, CACertificate: []byte(serverCA.CertificatePEM), RoutesRevision: bytes.Repeat([]byte{1}, 32), Hosted: true}
	request, err := NewAuthorizationRequest(connection, "01010101010101010101010101010101", identity)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(nonce, scope string, epoch uint64) controlplane.MountAuthorization {
		t.Helper()
		peer := sha256.Sum256(identity.PublicKey)
		token, e := productauth.Sign(productKey, productauth.Claims{Issuer: "workspace-product", Audience: "portablefs-manager", AuthorizationDomain: "org", Owner: "owner", Subject: "agent", VolumeID: volume.ID, Access: []string{"read", "write"}, PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: nonce, NotBefore: now.Add(-time.Second).Unix(), Expires: now.Add(10 * time.Minute).Unix(), RenewalScope: scope, RenewalEpoch: epoch})
		if e != nil {
			t.Fatal(e)
		}
		issueRequest, e := request.HostedIssueRequest(string(token), []string{"read", "write"})
		if e != nil {
			t.Fatal(e)
		}
		grant, e := manager.IssueMount(nonce, issueRequest)
		if e != nil {
			t.Fatal(e)
		}
		return grant
	}
	for _, wrong := range []struct {
		name, scope string
		epoch       uint64
	}{{"wrong-scope", "foreign-workspace", 1}, {"wrong-epoch", request.RenewalScope, 2}} {
		grant := issue(wrong.name, wrong.scope, wrong.epoch)
		response, e := request.HostedAuthorization(grant, "https://manager.example", "manager.example", []byte(serverCA.CertificatePEM))
		if e != nil {
			t.Fatal(e)
		}
		p, _ := response.Provision()
		if guest.AcceptProvision(t.Context(), p, func(context.Context) error { return nil }) == nil {
			t.Fatal("foreign scope/epoch provision accepted")
		}
	}
	// The wrong higher epoch really advanced the Manager fence. Move this guest
	// epoch through its actual durable revocation owner before fresh issuance.
	if err = guest.Reissue(identityRequest, true, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	identity, err = guest.EnsureIdentity(identityRequest)
	if err != nil {
		t.Fatal(err)
	}
	request, err = NewAuthorizationRequest(connection, "02020202020202020202020202020202", identity)
	if err != nil {
		t.Fatal(err)
	}
	grant := issue("correct", request.RenewalScope, identity.RenewalEpoch)
	response, err := request.HostedAuthorization(grant, "https://manager.example", "manager.example", []byte(serverCA.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	p, err := response.Provision()
	if err != nil {
		t.Fatal(err)
	}
	if err = guest.AcceptProvision(t.Context(), p, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	session := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16))
	refresh := controlplane.RefreshMountEnrollmentRequest{ClientCSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: identity.Csr})), SessionID: session, Sequence: 1}
	first, err := manager.RefreshMountEnrollment("renew-one", grant.EnrollmentID, refresh)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := manager.RefreshMountEnrollment("renew-one-new-transport", grant.EnrollmentID, refresh)
	if err != nil || !reflect.DeepEqual(first, replay) {
		t.Fatal("renewal exact-sequence replay changed grant", err)
	}
	refresh.Sequence = 3
	if _, err = manager.RefreshMountEnrollment("renew-skipped", grant.EnrollmentID, refresh); err == nil {
		t.Fatal("skipped renewal sequence accepted")
	}
	refresh.Sequence = 2
	refresh.SessionID = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 16))
	if _, err = manager.RefreshMountEnrollment("renew-foreign-session", grant.EnrollmentID, refresh); err == nil {
		t.Fatal("foreign renewal session accepted")
	}
	if err = guest.Reissue(identityRequest, false, func() error { return fmt.Errorf("kernel cleanup unconfirmed") }); err == nil {
		t.Fatal("replacement before exact cleanup")
	}
	if err = guest.Reissue(identityRequest, false, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	replacement, err := guest.EnsureIdentity(identityRequest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(replacement.Mount.Incarnation, identity.Mount.Incarnation) || !bytes.Equal(replacement.PublicKey, identity.PublicKey) || replacement.RenewalEpoch != identity.RenewalEpoch {
		t.Fatal("replacement changed persistent identity or retained old MountID")
	}
	if err = guest.AcceptProvision(t.Context(), p, func(context.Context) error { return nil }); err == nil {
		t.Fatal("old initial grant installed after replacement")
	}
}
