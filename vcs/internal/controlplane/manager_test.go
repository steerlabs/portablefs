package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/productauth"
	"github.com/steerlabs/portablefs/vcs/internal/volumecap"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type managerHarness struct {
	manager    *Manager
	store      *Store
	now        *time.Time
	productKey ed25519.PrivateKey
}

func newManagerHarness(t *testing.T) managerHarness {
	t.Helper()
	planPublic, planPrivate, _ := ed25519.GenerateKey(nil)
	_ = planPublic
	capabilityPublic, capabilityPrivate, _ := ed25519.GenerateKey(nil)
	_ = capabilityPublic
	productPublic, productPrivate, _ := ed25519.GenerateKey(nil)
	authorityCA := testCA(t, "authority-ca")
	clientCA := testCA(t, "client-ca")
	store, err := OpenStore(filepath.Join(t.TempDir(), "manager.state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Unix(1_900_000_000, 0).UTC()
	manager, err := NewManager(ManagerConfig{
		Store: store, PlanPrivateKey: planPrivate, CapabilityPrivateKey: capabilityPrivate,
		ProductIssuers: map[string]ed25519.PublicKey{"opensteer": productPublic},
		AuthorityCA:    authorityCA, ClientCA: clientCA, Now: func() time.Time { return now }, ReleaseID: "v3.1.0-test",
		PlanLifetime: 10 * time.Minute, GrantLifetime: 10 * time.Minute, ProductMaxLifetime: 15 * time.Minute,
		ClientCertLifetime: time.Hour, AuthorityCertLifetime: 24 * time.Hour,
		ObservedStaleAfter: 2 * time.Minute, ClockSkew: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return managerHarness{manager: manager, store: store, now: &now, productKey: productPrivate}
}

func TestVolumeProvisioningMountAuthorizationAndRestart(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("register-1", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "us-west-2a",
		AuthorityHost: "cell.example.test", AuthorityDNSZone: "cell.example.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	volume, err := h.manager.CreateVolume("create-1", CreateVolumeRequest{
		AuthorizationDomain: "org-1", Owner: "user-1", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if volume.State != VolumeProvisioning || volume.ProjectID == 0 || volume.ServiceUID == 0 {
		t.Fatalf("new volume = %+v", volume)
	}
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	if len(plan.Volumes) != 1 || plan.Volumes[0].Phase != cellplan.PhaseProvision {
		t.Fatalf("initial plan = %+v", plan)
	}

	_, authorityCSR := testCSR(t)
	cell, err = h.manager.ObserveCell("observe-csr", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.ProjectID,
			ServiceUID: volume.ServiceUID, ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort,
			Provisioned: true, AuthorityCSRPEM: authorityCSR,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	if plan.Volumes[0].Phase != cellplan.PhaseServe || plan.Volumes[0].AuthorityCertificate == "" {
		t.Fatalf("certificate plan = %+v", plan.Volumes[0])
	}
	cell, err = h.manager.ObserveCell("observe-ready", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.ProjectID,
			ServiceUID: volume.ServiceUID, ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort,
			Provisioned: true, AuthorityRunning: true,
		}},
	})
	if err != nil || cell.Health != CellHealthy {
		t.Fatalf("ready observation = %+v, %v", cell, err)
	}
	volume, _ = h.manager.GetVolume(volume.ID)
	if volume.State != VolumeReady {
		t.Fatalf("ready volume state = %s", volume.State)
	}

	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	productToken := signedProductAuthorization(t, h, volume.Volume, peer, "mount-1", []string{"write"})
	request := IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: productToken, ClientCSRPEM: clientCSR, Access: []string{"write"},
	}
	authorization, err := h.manager.IssueMount("mount-request-1", request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := h.manager.IssueMount("mount-request-1", request)
	if err != nil || replayed.Capability != authorization.Capability || replayed.ClientCertificatePEM != authorization.ClientCertificatePEM {
		t.Fatalf("idempotent mount = %+v, %v", replayed, err)
	}
	request.Access = []string{"read"}
	if _, err := h.manager.IssueMount("mount-request-1", request); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("idempotency reuse = %v", err)
	}
	capabilityPublic := h.manager.cfg.CapabilityPrivateKey.Public().(ed25519.PublicKey)
	productPublic := h.productKey.Public().(ed25519.PublicKey)
	capAuthorizer := &volumecap.Authorizer{
		PublicKey: capabilityPublic, ProductPublicKey: productPublic, ProductIssuer: "opensteer", ProductAudience: "portablefs-manager",
		AuthorizationDomain: volume.AuthorizationDomain, Owner: volume.Owner, CellID: volume.CellID,
		AuthorityID: volume.AuthorityID, AuthorityGeneration: volume.AuthorityGeneration,
		Now: func() time.Time { return *h.now }, MaxLifetime: 15 * time.Minute, MaxRetainedNonces: 32,
	}
	if _, err := capAuthorizer.Verify(volume.ID, []byte(authorization.Capability), peer); err != nil {
		t.Fatalf("hosted authority refused manager grant: %v", err)
	}
	var sessionID volumeserver.SessionID
	copy(sessionID[:], []byte("session-id-12345"))
	reauthorizationRequest := ReauthorizeMountRequest{
		VolumeID:             volume.ID,
		ProductAuthorization: signedProductAuthorization(t, h, volume.Volume, peer, "mount-2", []string{"read"}),
		ClientCSRPEM:         clientCSR, Access: []string{"read"},
		SessionID: base64.RawURLEncoding.EncodeToString(sessionID[:]), Sequence: 1,
	}
	reauthorization, err := h.manager.ReauthorizeMount("reauthorize-1", reauthorizationRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedReauthorization, err := h.manager.ReauthorizeMount("reauthorize-1", reauthorizationRequest)
	if err != nil || replayedReauthorization.Capability != reauthorization.Capability ||
		replayedReauthorization.ClientCertificatePEM != reauthorization.ClientCertificatePEM {
		t.Fatalf("idempotent reauthorization = %+v, %v", replayedReauthorization, err)
	}
	renewedAccess, _, err := capAuthorizer.VerifyReauthorization(volume.ID, sessionID, 1, []byte(reauthorization.Capability), peer)
	if err != nil || renewedAccess.Access != volumeserver.AccessRead {
		t.Fatalf("hosted reauthorization = %+v, %v", renewedAccess, err)
	}

	volume, err = h.manager.RestartVolume("restart-1", RestartVolumeRequest{VolumeID: volume.ID, Reason: "rotate authority"})
	if err != nil || volume.State != VolumeFencing {
		t.Fatalf("restart = %+v, %v", volume, err)
	}
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	if plan.Volumes[0].Phase != cellplan.PhaseFence {
		t.Fatalf("fencing plan = %+v", plan.Volumes[0])
	}
	volume, err = h.manager.ConfirmStrictMountsFenced("fence-proof-1", ConfirmStrictFenceRequest{
		VolumeID: volume.ID, EvidenceSHA256: EvidenceHash([]byte("external client-host fence receipt")),
	})
	if err != nil || !volume.PriorStrictFenced {
		t.Fatalf("strict fence = %+v, %v", volume, err)
	}
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	_, err = h.manager.ObserveCell("observe-absent", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.ProjectID,
			ServiceUID: volume.ServiceUID, ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort,
			Provisioned: true, AuthorityAbsent: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	volume, _ = h.manager.GetVolume(volume.ID)
	if volume.State != VolumeProvisioning || volume.AuthorityGeneration != 2 || volume.AuthorityCertificate != "" {
		t.Fatalf("replacement authority state = %+v", volume.Volume)
	}
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	if !plan.Volumes[0].PriorStrictFenced {
		t.Fatal("replacement plan lost the external strict-mount fence proof")
	}
}

func TestCreateVolumeRejectsQuotaNotRepresentableInXFSKiB(t *testing.T) {
	h := newManagerHarness(t)
	_, err := h.manager.CreateVolume("unaligned-quota", CreateVolumeRequest{
		AuthorizationDomain: "org-1", Owner: "user-1", ProductIssuer: "opensteer",
		QuotaBytes: (1 << 30) + 1, QuotaInodes: 100_000,
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("unaligned XFS quota = %v, want ErrInvalid", err)
	}
}

func TestManagerReleaseUpgradeAdvancesTheSignedPlanGeneration(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("register-release-upgrade", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "us-west-2a",
		AuthorityHost: "cell.example.test", AuthorityDNSZone: "cell.example.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	before := verifiedPlan(t, h.manager, cell.ID, *h.now)

	upgradedConfig := h.manager.cfg
	upgradedConfig.ReleaseID = "v3.2.0-test"
	upgraded, err := NewManager(upgradedConfig)
	if err != nil {
		t.Fatal(err)
	}
	after := verifiedPlan(t, upgraded, cell.ID, *h.now)
	if after.ReleaseID != upgradedConfig.ReleaseID || after.Generation != before.Generation+1 {
		t.Fatalf("upgraded plan = release %q generation %d, want release %q generation %d",
			after.ReleaseID, after.Generation, upgradedConfig.ReleaseID, before.Generation+1)
	}
	replayed := verifiedPlan(t, upgraded, cell.ID, *h.now)
	if replayed.Generation != after.Generation {
		t.Fatalf("replayed upgraded plan generation = %d, want %d", replayed.Generation, after.Generation)
	}
	if err := h.store.View(func(state State) error {
		if got := state.Cells[cell.ID].PlanReleaseID; got != upgradedConfig.ReleaseID {
			t.Fatalf("durable plan release = %q, want %q", got, upgradedConfig.ReleaseID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestObservationCannotSwapIsolationIdentity(t *testing.T) {
	h := newManagerHarness(t)
	cell, _ := h.manager.RegisterCell("register", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.test",
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	volume, _ := h.manager.CreateVolume("create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	cell, err := h.manager.ObserveCell("bad-observation", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.ProjectID + 1,
			ServiceUID: volume.ServiceUID, ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort,
		}},
	})
	if err != nil || cell.Health != CellQuarantined {
		t.Fatalf("bad observation = %+v, %v", cell, err)
	}
	volume, _ = h.manager.GetVolume(volume.ID)
	if volume.State != VolumeQuarantined {
		t.Fatalf("identity-confused volume was not quarantined: %+v", volume)
	}
}

func TestObservationCannotOmitAssignedVolume(t *testing.T) {
	h := newManagerHarness(t)
	cell, _ := h.manager.RegisterCell("register", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.test",
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	volume, _ := h.manager.CreateVolume("create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	cell, err := h.manager.ObserveCell("omitted", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix(), Volumes: nil,
	})
	if err != nil || cell.Health != CellQuarantined {
		t.Fatalf("omitted observation = %+v, %v", cell, err)
	}
	got, _ := h.manager.GetVolume(volume.ID)
	if got.State != VolumeQuarantined {
		t.Fatalf("omitted volume state = %s", got.State)
	}
}

func TestHeartbeatIsLiveFailClosedStateAndDoesNotPretendToSurviveRestart(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("register", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.test",
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := CellHeartbeat{
		CellID: cell.ID, PlanGeneration: cell.PlanGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-r1", HelperReleaseID: "helper-r1", ObservedUnix: h.now.Unix(),
	}
	if err := h.manager.HeartbeatCell(heartbeat); err != nil || !h.manager.cellFresh(cell, h.now.Unix()) {
		t.Fatalf("live heartbeat = %v, fresh=%v", err, h.manager.cellFresh(cell, h.now.Unix()))
	}
	restarted, err := NewManager(h.manager.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.cellFresh(cell, h.now.Unix()) {
		t.Fatal("a manager restart inherited a heartbeat it did not observe")
	}
	if err := restarted.HeartbeatCell(heartbeat); err != nil || !restarted.cellFresh(cell, h.now.Unix()) {
		t.Fatalf("post-restart heartbeat = %v, fresh=%v", err, restarted.cellFresh(cell, h.now.Unix()))
	}
	heartbeat.PlanGeneration++
	if err := restarted.HeartbeatCell(heartbeat); !errors.Is(err, ErrConflict) {
		t.Fatalf("ahead heartbeat = %v", err)
	}
}

func TestAuthorityCertificateRenewsOnTheSameGenerationAndCSR(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("register", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.test",
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	volume, err := h.manager.CreateVolume("create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, csr := testCSR(t)
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	observe := func(id string, planGeneration uint64, csrPEM string) {
		t.Helper()
		_, err := h.manager.ObserveCell(id, CellObservation{
			CellID: cell.ID, PlanGeneration: planGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(),
			AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix(),
			Volumes: []VolumeObservation{{
				VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.ProjectID, ServiceUID: volume.ServiceUID,
				ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort, Provisioned: true, AuthorityRunning: true,
				AuthorityCSRPEM: csrPEM,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	observe("initial-csr", plan.Generation, csr)
	first, _ := h.manager.GetVolume(volume.ID)
	if first.AuthorityCertificate == "" || first.AuthorityCertExpires == 0 {
		t.Fatalf("initial authority identity = %+v", first.Volume)
	}
	*h.now = h.now.Add(17 * time.Hour)
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	observe("renew-csr", plan.Generation, csr)
	renewed, _ := h.manager.GetVolume(volume.ID)
	if renewed.AuthorityGeneration != first.AuthorityGeneration || renewed.AuthorityCSRPEM != csr ||
		renewed.AuthorityCertificate == first.AuthorityCertificate || renewed.AuthorityCertExpires <= first.AuthorityCertExpires {
		t.Fatalf("renewed authority identity = %+v, first expiry=%d", renewed.Volume, first.AuthorityCertExpires)
	}
}

func TestAuthorityCSRSwapWithinGenerationQuarantinesVolume(t *testing.T) {
	h := newManagerHarness(t)
	cell, _ := h.manager.RegisterCell("register", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.test",
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	volume, _ := h.manager.CreateVolume("create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	_, firstCSR := testCSR(t)
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	base := CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix(),
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.ProjectID, ServiceUID: volume.ServiceUID,
			ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort, Provisioned: true, AuthorityCSRPEM: firstCSR,
		}},
	}
	if _, err := h.manager.ObserveCell("initial", base); err != nil {
		t.Fatal(err)
	}
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	_, changedCSR := testCSR(t)
	base.PlanGeneration = plan.Generation
	base.Volumes[0].AuthorityCSRPEM = changedCSR
	cell, err := h.manager.ObserveCell("swapped", base)
	if err != nil || cell.Health != CellQuarantined {
		t.Fatalf("CSR swap observation = %+v, %v", cell, err)
	}
	got, _ := h.manager.GetVolume(volume.ID)
	if got.State != VolumeQuarantined {
		t.Fatalf("CSR-swapped volume state = %s", got.State)
	}
}

func TestReadyAuthorityHostFailureFencesForRetryWithoutIdentityQuarantine(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("register", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.test",
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	volume, err := h.manager.CreateVolume("create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, csr := testCSR(t)
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	base := VolumeObservation{
		VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityGeneration, ProjectID: volume.ProjectID,
		ServiceUID: volume.ServiceUID, ServiceGID: volume.ServiceGID, ListenPort: volume.ListenPort, Provisioned: true,
	}
	withCSR := base
	withCSR.AuthorityCSRPEM = csr
	if _, err := h.manager.ObserveCell("csr", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix(), Volumes: []VolumeObservation{withCSR},
	}); err != nil {
		t.Fatal(err)
	}
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	base.AuthorityRunning = true
	if _, err := h.manager.ObserveCell("ready", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix(), Volumes: []VolumeObservation{base},
	}); err != nil {
		t.Fatal(err)
	}
	base.AuthorityRunning = false
	base.Error = "systemd reported the authority inactive"
	cell, err = h.manager.ObserveCell("host-error", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix(), Volumes: []VolumeObservation{base},
	})
	if err != nil || cell.Health != CellDegraded {
		t.Fatalf("host failure cell = %+v, %v", cell, err)
	}
	got, err := h.manager.GetVolume(volume.ID)
	if err != nil || got.State != VolumeFencing || got.QuarantineReason != "" {
		t.Fatalf("host failure volume = %+v, %v", got, err)
	}
}

func verifiedPlan(t *testing.T, manager *Manager, cellID string, now time.Time) cellplan.Plan {
	t.Helper()
	envelope, err := manager.CellPlan(cellID)
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := cellplan.Verify(manager.cfg.PlanPrivateKey.Public().(ed25519.PublicKey), envelope, cellID, now, time.Second, manager.cfg.PlanLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func signedProductAuthorization(t *testing.T, h managerHarness, volume Volume, peer [32]byte, nonce string, access []string) string {
	t.Helper()
	token, err := productauth.Sign(h.productKey, productauth.Claims{
		Issuer: volume.ProductIssuer, Audience: "portablefs-manager", AuthorizationDomain: volume.AuthorizationDomain,
		Owner: volume.Owner, Subject: "agent-session", VolumeID: volume.ID, Access: access,
		PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: nonce,
		NotBefore: h.now.Add(-time.Second).Unix(), Expires: h.now.Add(12 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(token)
}

func testCSR(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "local-key"}}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func testCA(t *testing.T, commonName string) *CertificateAuthority {
	t.Helper()
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_800_000_000, 0)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCertificateAuthority(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}
