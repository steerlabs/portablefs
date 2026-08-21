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
	"fmt"
	"math/big"
	"path/filepath"
	"slices"
	"sync"
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
	enrollmentCA := testCA(t, "enrollment-ca")
	store, err := OpenStore(filepath.Join(t.TempDir(), "manager.state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Unix(1_900_000_000, 0).UTC()
	manager, err := NewManager(ManagerConfig{
		Store: store, PlanPrivateKey: planPrivate, CapabilityPrivateKey: capabilityPrivate,
		ProductIssuers: map[string]ed25519.PublicKey{"opensteer": productPublic},
		AuthorityCA:    authorityCA, ClientCA: clientCA, EnrollmentCA: enrollmentCA,
		Now: func() time.Time { return now }, ReleaseID: "v3.1.0-test",
		PlanLifetime: 10 * time.Minute, GrantLifetime: 10 * time.Minute, ProductMaxLifetime: 15 * time.Minute,
		EnrollmentLifetime: 24 * time.Hour,
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
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	volume, err := h.manager.CreateVolume("create-1", CreateVolumeRequest{
		AuthorizationDomain: "org-1", Owner: "user-1", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if volume.State != VolumeProvisioning || volume.Placement.ProjectID == 0 || volume.Placement.ServiceUID == 0 {
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
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.Placement.ProjectID,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
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
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.Placement.ProjectID,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
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
	standalone, err := h.manager.IssueMount("standalone-mount", IssueMountRequest{
		VolumeID:             volume.ID,
		ProductAuthorization: signedProductAuthorization(t, h, volume.Volume, peer, "standalone-mount", []string{"read"}),
		ClientCSRPEM:         clientCSR, Access: []string{"read"},
	})
	if err != nil || standalone.EnrollmentID != "" || standalone.EnrollmentCertificatePEM != "" || standalone.EnrollmentExpiresUnix != 0 {
		t.Fatalf("standalone mount received an unrequested enrollment = %+v, %v", standalone, err)
	}
	productToken := signedProductAuthorization(t, h, volume.Volume, peer, "mount-1", []string{"write"})
	request := IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: productToken, ClientCSRPEM: clientCSR, Access: []string{"write"},
		AutomaticReauthorization: true,
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
		AuthorizationDomain: volume.AuthorizationDomain, Owner: volume.Owner, CellID: volume.Placement.CellID,
		AuthorityID: volume.Placement.AuthorityID, AuthorityGeneration: volume.AuthorityEpoch,
		Now: func() time.Time { return *h.now }, MaxLifetime: 15 * time.Minute, MaxRetainedNonces: 32,
	}
	initialAccess, err := capAuthorizer.Verify(volume.ID, []byte(authorization.Capability), peer)
	if err != nil {
		t.Fatalf("hosted authority refused manager grant: %v", err)
	}
	runtimeAuthority, err := volumeserver.New(volume.ID, volumeserver.Config{
		SessionLease: 10 * time.Minute, MaxReplaySlots: 4, MaxSessions: 4, MaxLockRecords: 16,
		Now: func() time.Time { return *h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeCredential, err := runtimeAuthority.AttachActiveForTest(1, volumeserver.PeerIdentity(peer), initialAccess)
	if err != nil {
		t.Fatalf("attach enrollment-owned authority session: %v", err)
	}
	if authorization.EnrollmentID == "" || authorization.EnrollmentCertificatePEM == "" || authorization.EnrollmentExpiresUnix <= authorization.ExpiresUnix {
		t.Fatalf("initial mount omitted bounded automatic enrollment: %+v", authorization)
	}
	if initialAccess.MountEnrollmentID != authorization.EnrollmentID {
		t.Fatalf("initial authority session owner = %q, want %q", initialAccess.MountEnrollmentID, authorization.EnrollmentID)
	}
	unboundManualSession := base64.RawURLEncoding.EncodeToString([]byte("other-session-id"))
	unboundManual, err := h.manager.ReauthorizeMount("unbound-independent-session", ReauthorizeMountRequest{
		VolumeID:             volume.ID,
		ProductAuthorization: signedProductAuthorization(t, h, volume.Volume, peer, "unbound-independent-session", []string{"read"}),
		ClientCSRPEM:         clientCSR, Access: []string{"read"}, SessionID: unboundManualSession, Sequence: 1,
	})
	if err != nil || unboundManual.SessionID != unboundManualSession || unboundManual.EnrollmentID != "" {
		t.Fatalf("unbound enrollment blocked an unrelated session = %+v, %v", unboundManual, err)
	}
	enrollmentBlock, _ := pem.Decode([]byte(authorization.EnrollmentCertificatePEM))
	if enrollmentBlock == nil {
		t.Fatal("mount enrollment certificate is not PEM")
	}
	enrollmentLeaf, err := x509.ParseCertificate(enrollmentBlock.Bytes)
	if err != nil || len(enrollmentLeaf.URIs) != 1 || enrollmentLeaf.URIs[0].String() != "spiffe://portablefs/mount-enrollment/"+authorization.EnrollmentID {
		t.Fatalf("mount enrollment identity = %v, %v", enrollmentLeaf.URIs, err)
	}
	enrollmentRoots := x509.NewCertPool()
	enrollmentRoots.AddCert(h.manager.cfg.EnrollmentCA.Certificate)
	if _, err := enrollmentLeaf.Verify(x509.VerifyOptions{
		Roots: enrollmentRoots, CurrentTime: *h.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("mount enrollment identity is not enrollment-CA scoped: %v", err)
	}
	shortLivedRoots := x509.NewCertPool()
	shortLivedRoots.AddCert(h.manager.cfg.ClientCA.Certificate)
	if _, err := enrollmentLeaf.Verify(x509.VerifyOptions{
		Roots: shortLivedRoots, CurrentTime: *h.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("mount enrollment identity chained to the authority-facing short-lived client CA")
	}
	sessionID := runtimeCredential.ID
	sessionEncoded := base64.RawURLEncoding.EncodeToString(sessionID[:])
	automaticRequest := RefreshMountEnrollmentRequest{ClientCSRPEM: clientCSR, SessionID: sessionEncoded, Sequence: 1}
	automatic, err := h.manager.RefreshMountEnrollment("automatic-1", authorization.EnrollmentID, automaticRequest)
	if err != nil {
		t.Fatal(err)
	}
	sequenceAfterFirstRefresh := h.store.sequence
	// Natural tuple idempotency is independent of the HTTP retry key. This is
	// what prevents two proofs for one authority sequence after a lost reply.
	automaticRetry, err := h.manager.RefreshMountEnrollment("automatic-1-retry", authorization.EnrollmentID, automaticRequest)
	if err != nil || automaticRetry.Capability != automatic.Capability || automaticRetry.ClientCertificatePEM != automatic.ClientCertificatePEM {
		t.Fatalf("natural automatic idempotency = %+v, %v", automaticRetry, err)
	}
	if h.store.sequence != sequenceAfterFirstRefresh {
		t.Fatal("an exact automatic refresh retry appended another durable state record")
	}
	if err := h.store.View(func(state State) error {
		if len(state.MountAuthorizationContexts) != 1 {
			t.Fatalf("mount authorization contexts = %d, want one deduplicated Manager context", len(state.MountAuthorizationContexts))
		}
		enrollment := state.MountEnrollments[authorization.EnrollmentID]
		if enrollment.Owner != volume.Owner || enrollment.LastAuthorization == nil || enrollment.LastAuthorizationContext == "" ||
			enrollment.LastAuthorization.ClientCertificatePEM != automatic.ClientCertificatePEM ||
			enrollment.LastAuthorization.Capability != automatic.Capability {
			t.Fatalf("stored automatic replay = %+v", enrollment)
		}
		context := state.MountAuthorizationContexts[enrollment.LastAuthorizationContext]
		if context.AuthorityCAPEM != automatic.AuthorityCAPEM || context.ReleaseID != automatic.ReleaseID {
			t.Fatalf("deduplicated automatic replay context = %+v", context)
		}
		for _, receipt := range state.Receipts {
			if receipt.Operation == "refresh-mount-enrollment" {
				t.Fatal("automatic refresh created an unbounded generic response receipt")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	automaticAccess, automaticProof, err := capAuthorizer.VerifyReauthorization(volume.ID, sessionID, 1, []byte(automatic.Capability), peer)
	if err != nil || automaticAccess.Access != (volumeserver.AccessRead|volumeserver.AccessWrite) {
		t.Fatalf("enrollment-backed authority grant = %+v, %v", automaticAccess, err)
	}
	if err := runtimeAuthority.Reauthorize(runtimeCredential, automaticAccess, 1, automaticProof); err != nil {
		t.Fatalf("install Manager enrollment grant into live authority session: %v", err)
	}
	automaticRequest.Sequence = 2
	if _, err := h.manager.RefreshMountEnrollment("automatic-too-fast", authorization.EnrollmentID, automaticRequest); !errors.Is(err, ErrConflict) {
		t.Fatalf("automatic sequence advanced faster than its grant window = %v", err)
	}
	automaticRequest.Sequence = 3
	if _, err := h.manager.RefreshMountEnrollment("automatic-gap", authorization.EnrollmentID, automaticRequest); !errors.Is(err, ErrConflict) {
		t.Fatalf("automatic sequence gap = %v", err)
	}
	*h.now = h.now.Add(3 * time.Minute)
	if err := h.manager.HeartbeatCell(CellHeartbeat{
		CellID: cell.ID, PlanGeneration: cell.PlanGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
	}); err != nil {
		t.Fatalf("refresh cell liveness before sequence two: %v", err)
	}
	automaticRequest.Sequence = 2
	automaticTwo, err := h.manager.RefreshMountEnrollment("automatic-2", authorization.EnrollmentID, automaticRequest)
	if err != nil {
		t.Fatalf("automatic sequence two: %v", err)
	}
	automaticAccessTwo, automaticProofTwo, err := capAuthorizer.VerifyReauthorization(volume.ID, sessionID, 2, []byte(automaticTwo.Capability), peer)
	if err != nil || !automaticAccessTwo.Deadline.After(initialAccess.Deadline) {
		t.Fatalf("extended enrollment-backed authority grant = %+v, %v", automaticAccessTwo, err)
	}
	if err := runtimeAuthority.Reauthorize(runtimeCredential, automaticAccessTwo, 2, automaticProofTwo); err != nil {
		t.Fatalf("extend the existing authority session without remount: %v", err)
	}
	manualOwnerConflict := ReauthorizeMountRequest{
		VolumeID:             volume.ID,
		ProductAuthorization: signedProductAuthorization(t, h, volume.Volume, peer, "manual-owner-conflict", []string{"read"}),
		ClientCSRPEM:         clientCSR, Access: []string{"read"}, SessionID: sessionEncoded, Sequence: 1,
	}
	if _, err := h.manager.ReauthorizeMount("manual-owner-conflict", manualOwnerConflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("manual issuer competed with active enrollment = %v", err)
	}
	manualPublic, manualCSR := testCSR(t)
	manualSPKI, err := x509.MarshalPKIXPublicKey(manualPublic)
	if err != nil {
		t.Fatal(err)
	}
	manualPeer := sha256.Sum256(manualSPKI)
	var manualSessionID volumeserver.SessionID
	copy(manualSessionID[:], []byte("manual-session-1"))
	manualSessionEncoded := base64.RawURLEncoding.EncodeToString(manualSessionID[:])
	reauthorizationRequest := ReauthorizeMountRequest{
		VolumeID:             volume.ID,
		ProductAuthorization: signedProductAuthorization(t, h, volume.Volume, manualPeer, "mount-2", []string{"read"}),
		ClientCSRPEM:         manualCSR, Access: []string{"read"},
		SessionID: manualSessionEncoded, Sequence: 1,
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
	renewedAccess, _, err := capAuthorizer.VerifyReauthorization(volume.ID, manualSessionID, 1, []byte(reauthorization.Capability), manualPeer)
	if err != nil || renewedAccess.Access != volumeserver.AccessRead {
		t.Fatalf("hosted reauthorization = %+v, %v", renewedAccess, err)
	}
	if _, err := h.manager.RevokeVolumeMountEnrollment("opensteer", volume.ID, authorization.EnrollmentID, TerminateMountEnrollmentRequest{Reason: "product access revoked"}); err != nil {
		t.Fatalf("revoke mount enrollment: %v", err)
	}
	sequenceAfterRevocation := h.store.sequence
	closedAfterRevoke, err := h.manager.CloseMountEnrollment(
		"close-after-revoke", authorization.EnrollmentID, TerminateMountEnrollmentRequest{Reason: "mount detached"},
	)
	if err != nil || closedAfterRevoke.State != MountEnrollmentRevoked || h.store.sequence != sequenceAfterRevocation {
		t.Fatalf("terminal enrollment retry = %+v, sequence=%d want=%d, err=%v", closedAfterRevoke, h.store.sequence, sequenceAfterRevocation, err)
	}
	automaticRequest.Sequence = 2
	if _, err := h.manager.RefreshMountEnrollment("automatic-after-revoke", authorization.EnrollmentID, automaticRequest); !errors.Is(err, ErrEnrollmentEnded) {
		t.Fatalf("refresh after enrollment revocation = %v", err)
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
	if err != nil || !volume.Placement.PriorStrictFenced {
		t.Fatalf("strict fence = %+v, %v", volume, err)
	}
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	_, err = h.manager.ObserveCell("observe-absent", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.Placement.ProjectID,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
			Provisioned: true, AuthorityAbsent: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	volume, _ = h.manager.GetVolume(volume.ID)
	if volume.State != VolumeProvisioning || volume.AuthorityEpoch != 2 || volume.Placement.AuthorityCertificatePEM != "" {
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

func TestMountEnrollmentAdmissionBoundsActiveOwnersWithoutTombstoneExhaustion(t *testing.T) {
	active := func(id, authorizationDomain, volume string, updated int64) MountEnrollment {
		return MountEnrollment{ID: id, AuthorizationDomain: authorizationDomain, VolumeID: volume, State: MountEnrollmentActive, UpdatedUnix: updated}
	}
	terminal := func(id string, updated int64) MountEnrollment {
		return MountEnrollment{ID: id, ProductIssuer: "old-product", VolumeID: "old-volume", State: MountEnrollmentClosed, UpdatedUnix: updated}
	}

	perVolume := NewState()
	for i := 0; i < MaxActiveMountEnrollmentsPerVolume; i++ {
		id := fmt.Sprintf("volume-%04d", i)
		perVolume.MountEnrollments[id] = active(id, "product-a", "volume-a", 100)
	}
	if err := admitMountEnrollment(&perVolume, Volume{ID: "volume-a", AuthorizationDomain: "tenant-a"}); !errors.Is(err, ErrEnrollmentCapacity) {
		t.Fatalf("per-volume admission = %v, want capacity refusal", err)
	}
	first := perVolume.MountEnrollments["volume-0000"]
	first.State = MountEnrollmentClosed
	perVolume.MountEnrollments[first.ID] = first
	if err := admitMountEnrollment(&perVolume, Volume{ID: "volume-a", AuthorizationDomain: "tenant-a"}); err != nil {
		t.Fatalf("terminal enrollment consumed active per-volume quota: %v", err)
	}

	perTenant := NewState()
	for i := 0; i < MaxActiveMountEnrollmentsPerAuthorizationDomain; i++ {
		id := fmt.Sprintf("tenant-%04d", i)
		perTenant.MountEnrollments[id] = active(id, "tenant-a", fmt.Sprintf("volume-%04d", i), 100)
	}
	if err := admitMountEnrollment(&perTenant, Volume{ID: "new-volume", AuthorizationDomain: "tenant-a"}); !errors.Is(err, ErrEnrollmentCapacity) {
		t.Fatalf("per-tenant admission = %v, want capacity refusal", err)
	}

	global := NewState()
	for i := 0; i < MaxActiveMountEnrollments; i++ {
		id := fmt.Sprintf("global-%04d", i)
		global.MountEnrollments[id] = active(id, fmt.Sprintf("tenant-%d", i/MaxActiveMountEnrollmentsPerAuthorizationDomain), fmt.Sprintf("volume-%d", i/MaxActiveMountEnrollmentsPerVolume), 100)
	}
	if err := admitMountEnrollment(&global, Volume{ID: "new-volume", AuthorizationDomain: "new-tenant"}); !errors.Is(err, ErrEnrollmentCapacity) {
		t.Fatalf("global admission = %v, want capacity refusal", err)
	}

	retained := NewState()
	for i := 0; i < MaxRetainedMountEnrollments; i++ {
		id := fmt.Sprintf("terminal-%04d", i)
		retained.MountEnrollments[id] = terminal(id, int64(i+1))
	}
	if err := admitMountEnrollment(&retained, Volume{ID: "new-volume", AuthorizationDomain: "new-tenant"}); err != nil {
		t.Fatalf("terminal tombstones exhausted new enrollment admission: %v", err)
	}
	if len(retained.MountEnrollments) != MaxRetainedMountEnrollments-1 {
		t.Fatalf("retained enrollment count = %d", len(retained.MountEnrollments))
	}
	if _, ok := retained.MountEnrollments["terminal-0000"]; ok {
		t.Fatal("admission did not evict the oldest terminal tombstone")
	}
}

func TestPruneMountEnrollmentsRemovesExpiredOwnersAndOrphanedReplayContexts(t *testing.T) {
	state := NewState()
	context := MountAuthorizationContext{AuthorityCAPEM: "ca", ReleaseID: "release"}
	contextID := mountAuthorizationContextID(context)
	state.MountAuthorizationContexts[contextID] = context
	state.MountEnrollments["expired"] = MountEnrollment{
		ID: "expired", State: MountEnrollmentActive, ExpiresUnix: 100,
		LastAuthorizationContext: contextID,
	}
	state.MountEnrollments["recent-terminal"] = MountEnrollment{
		ID: "recent-terminal", State: MountEnrollmentClosed, UpdatedUnix: 100,
	}
	state.MountEnrollments["old-terminal"] = MountEnrollment{
		ID: "old-terminal", State: MountEnrollmentRevoked, UpdatedUnix: 99,
	}
	now := int64(100) + int64(mountEnrollmentRetention/time.Second)
	if !pruneMountEnrollments(&state, now) {
		t.Fatal("prune reported no state change")
	}
	if _, ok := state.MountEnrollments["expired"]; ok {
		t.Fatal("expired active enrollment was retained")
	}
	if _, ok := state.MountEnrollments["recent-terminal"]; ok {
		t.Fatal("terminal enrollment at the retention boundary was retained")
	}
	if _, ok := state.MountEnrollments["old-terminal"]; ok {
		t.Fatal("old terminal enrollment was retained")
	}
	if len(state.MountAuthorizationContexts) != 0 {
		t.Fatal("orphaned replay context was retained")
	}
}

func TestScopedRenewalIssuanceRotatesSameEpochEnrollment(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	issue := func(requestID, scope string, epoch uint64) MountAuthorization {
		t.Helper()
		clientPublic, clientCSR := testCSR(t)
		peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
		if err != nil {
			t.Fatal(err)
		}
		peer := sha256.Sum256(peerSPKI)
		authorization, err := h.manager.IssueMount(requestID, IssueMountRequest{
			VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
				t, h, volume.Volume, peer, requestID, []string{"write"}, scope, epoch,
			),
			ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
		})
		if err != nil {
			t.Fatalf("issue %s: %v", requestID, err)
		}
		return authorization
	}

	first := issue("scope-epoch-2", "cloud-private-state:computer-1", 2)
	second := issue("scope-epoch-2-fresh-csr", "cloud-private-state:computer-1", 2)

	if err := h.store.View(func(state State) error {
		if got := state.RenewalFences[renewalFenceKey("opensteer", "cloud-private-state:computer-1")]; got != 2 {
			t.Fatalf("renewal fence = %d, want 2", got)
		}
		if enrollment := state.MountEnrollments[first.EnrollmentID]; enrollment.State != MountEnrollmentRevoked ||
			enrollment.TerminationReason != "renewal-scope-superseded" || enrollment.RenewalScope != "cloud-private-state:computer-1" || enrollment.RenewalEpoch != 2 {
			t.Fatalf("superseded enrollment = %+v", enrollment)
		}
		active := 0
		for _, enrollment := range state.MountEnrollments {
			if enrollment.ProductIssuer == "opensteer" && enrollment.RenewalScope == "cloud-private-state:computer-1" && enrollment.State == MountEnrollmentActive {
				active++
				if enrollment.ID != second.EnrollmentID {
					t.Fatalf("active scoped enrollment = %+v, want %s", enrollment, second.EnrollmentID)
				}
			}
		}
		if active != 1 {
			t.Fatalf("active scoped enrollments = %d, want 1", active)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExactScopedIssuanceReplayDoesNotRotateCreatedEnrollment(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	request := IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "scoped-replay", []string{"write"}, "cloud-private-state:computer-1", 2,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	}
	first, err := h.manager.IssueMount("scoped-replay", request)
	if err != nil {
		t.Fatal(err)
	}
	sequence := h.store.sequence
	replayed, err := h.manager.IssueMount("scoped-replay", request)
	if err != nil || replayed.EnrollmentID != first.EnrollmentID || h.store.sequence != sequence {
		t.Fatalf("scoped replay = %+v, sequence=%d want=%d, err=%v", replayed, h.store.sequence, sequence, err)
	}
	if err := h.store.View(func(state State) error {
		enrollment := state.MountEnrollments[first.EnrollmentID]
		if enrollment.State != MountEnrollmentActive || enrollment.TerminationReason != "" {
			t.Fatalf("replayed enrollment = %+v", enrollment)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestScopedStandaloneIssuanceRevokesOnlyLowerEpochEnrollments(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	issue := func(requestID string, epoch uint64, createEnrollment bool) MountAuthorization {
		t.Helper()
		clientPublic, clientCSR := testCSR(t)
		peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
		if err != nil {
			t.Fatal(err)
		}
		peer := sha256.Sum256(peerSPKI)
		authorization, err := h.manager.IssueMount(requestID, IssueMountRequest{
			VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
				t, h, volume.Volume, peer, requestID, []string{"write"}, "cloud-private-state:standalone", epoch,
			),
			ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: createEnrollment,
		})
		if err != nil {
			t.Fatal(err)
		}
		return authorization
	}
	lower := issue("standalone-lower", 1, true)
	if standalone := issue("standalone-advance", 2, false); standalone.EnrollmentID != "" {
		t.Fatalf("standalone issuance created enrollment %+v", standalone)
	}
	equal := issue("standalone-equal", 2, true)
	issue("standalone-equal-retry", 2, false)
	if err := h.store.View(func(state State) error {
		if enrollment := state.MountEnrollments[lower.EnrollmentID]; enrollment.State != MountEnrollmentRevoked || enrollment.TerminationReason != "renewal-scope-superseded" {
			t.Fatalf("lower standalone enrollment = %+v", enrollment)
		}
		if enrollment := state.MountEnrollments[equal.EnrollmentID]; enrollment.State != MountEnrollmentActive {
			t.Fatalf("equal standalone enrollment = %+v", enrollment)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalFenceBatchConvergesAtomically(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	issue := func(requestID, scope string, epoch uint64) MountAuthorization {
		t.Helper()
		clientPublic, clientCSR := testCSR(t)
		peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
		if err != nil {
			t.Fatal(err)
		}
		peer := sha256.Sum256(peerSPKI)
		authorization, err := h.manager.IssueMount(requestID, IssueMountRequest{
			VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
				t, h, volume.Volume, peer, requestID, []string{"write"}, scope, epoch,
			),
			ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return authorization
	}
	scopeA := "cloud-private-state:computer-a"
	scopeB := "cloud-private-state:computer-b"
	scopeC := "cloud-private-state:computer-c"
	activeA := issue("batch-scope-a-epoch-2", scopeA, 2)
	activeB := issue("batch-scope-b-epoch-5", scopeB, 5)

	sequence := h.store.sequence
	if _, err := h.manager.AdvanceRenewalFences("opensteer", AdvanceRenewalFencesRequest{
		Reason: "invalid-batch", Fences: []RenewalFence{{Scope: scopeC, Epoch: 4}, {Scope: "", Epoch: 1}},
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid batch = %v, want ErrInvalid", err)
	}
	if h.store.sequence != sequence {
		t.Fatalf("invalid batch sequence = %d, want %d", h.store.sequence, sequence)
	}
	if err := h.store.View(func(state State) error {
		if _, exists := state.RenewalFences[renewalFenceKey("opensteer", scopeC)]; exists {
			t.Fatal("invalid batch created its valid entry")
		}
		if enrollment := state.MountEnrollments[activeA.EnrollmentID]; enrollment.State != MountEnrollmentActive {
			t.Fatalf("invalid batch changed enrollment = %+v", enrollment)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	request := AdvanceRenewalFencesRequest{
		Reason: "cloud-computer-stopped",
		Fences: []RenewalFence{
			{Scope: scopeA, Epoch: 3},
			{Scope: scopeB, Epoch: 2},
			{Scope: scopeC, Epoch: 4},
			{Scope: scopeC, Epoch: 2},
			{Scope: scopeA, Epoch: 1},
		},
	}
	result, err := h.manager.AdvanceRenewalFences("opensteer", request)
	if err != nil {
		t.Fatal(err)
	}
	want := []RenewalFence{
		{Scope: scopeA, Epoch: 3},
		{Scope: scopeB, Epoch: 5},
		{Scope: scopeC, Epoch: 4},
		{Scope: scopeC, Epoch: 4},
		{Scope: scopeA, Epoch: 3},
	}
	if !slices.Equal(result.Fences, want) {
		t.Fatalf("batch response = %+v, want %+v", result.Fences, want)
	}
	if h.store.sequence != sequence+1 {
		t.Fatalf("batch sequence = %d, want one transaction after %d", h.store.sequence, sequence)
	}
	if err := h.store.View(func(state State) error {
		if enrollment := state.MountEnrollments[activeA.EnrollmentID]; enrollment.State != MountEnrollmentRevoked || enrollment.TerminationReason != request.Reason {
			t.Fatalf("lower-epoch enrollment = %+v", enrollment)
		}
		if enrollment := state.MountEnrollments[activeB.EnrollmentID]; enrollment.State != MountEnrollmentActive {
			t.Fatalf("exact-epoch enrollment = %+v", enrollment)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	sequence = h.store.sequence
	lower, err := h.manager.AdvanceRenewalFences("opensteer", AdvanceRenewalFencesRequest{
		Reason: "delayed-retry", Fences: []RenewalFence{{Scope: scopeA, Epoch: 1}, {Scope: scopeB, Epoch: 4}, {Scope: scopeC, Epoch: 3}},
	})
	if err != nil || lower.Fences[0].Epoch != 3 || lower.Fences[1].Epoch != 5 || lower.Fences[2].Epoch != 4 || h.store.sequence != sequence {
		t.Fatalf("lower batch = %+v, sequence=%d want=%d, err=%v", lower, h.store.sequence, sequence, err)
	}
}

func TestRenewalFenceBatchEpochBounds(t *testing.T) {
	h := newManagerHarness(t)
	for _, test := range []struct {
		name  string
		scope string
		epoch uint64
		valid bool
	}{
		{name: "zero", scope: "scope-zero", epoch: 0},
		{name: "one", scope: "scope-one", epoch: 1, valid: true},
		{name: "max", scope: "scope-max", epoch: productauth.MaxRenewalEpoch, valid: true},
		{name: "max-plus-one", scope: "scope-max-plus-one", epoch: productauth.MaxRenewalEpoch + 1},
		{name: "uint64-max", scope: "scope-uint64-max", epoch: ^uint64(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := h.manager.AdvanceRenewalFences("opensteer", AdvanceRenewalFencesRequest{
				Reason: "epoch-boundary", Fences: []RenewalFence{{Scope: test.scope, Epoch: test.epoch}},
			})
			if test.valid {
				if err != nil || len(response.Fences) != 1 || response.Fences[0].Epoch != test.epoch {
					t.Fatalf("AdvanceRenewalFences epoch %d = %+v, %v", test.epoch, response, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("AdvanceRenewalFences epoch %d = %v, want ErrInvalid", test.epoch, err)
			}
		})
	}
}

func TestRenewalFenceBatchScopeSyntax(t *testing.T) {
	h := newManagerHarness(t)
	for _, test := range []struct {
		name  string
		scope string
		valid bool
	}{
		{name: "less-than", scope: "cloud-private-state:clc_<uuid"},
		{name: "greater-than", scope: "cloud-private-state:clc_>uuid"},
		{name: "ampersand", scope: "cloud-private-state:clc_&uuid"},
		{name: "control", scope: "cloud-private-state:clc_\n"},
		{name: "unicode", scope: "cloud-private-state:clc_é"},
		{name: "identifier", scope: "cloud-private-state:clc_123e4567-e89b-12d3-a456-426614174000", valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := h.manager.AdvanceRenewalFences("opensteer", AdvanceRenewalFencesRequest{
				Reason: "scope-syntax", Fences: []RenewalFence{{Scope: test.scope, Epoch: 1}},
			})
			if test.valid {
				if err != nil || len(response.Fences) != 1 || response.Fences[0].Scope != test.scope {
					t.Fatalf("AdvanceRenewalFences scope %q = %+v, %v", test.scope, response, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("AdvanceRenewalFences scope %q = %v, want ErrInvalid", test.scope, err)
			}
		})
	}
}

func TestRenewalFenceRejectsStaleIssuance(t *testing.T) {
	h := newManagerHarness(t)
	cell, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	if _, err := h.manager.AdvanceRenewalFences("opensteer", AdvanceRenewalFencesRequest{
		Reason: "cloud-computer-stopped", Fences: []RenewalFence{{Scope: "cloud-private-state:computer-1", Epoch: 3}},
	}); err != nil {
		t.Fatal(err)
	}

	staleToken := signedProductAuthorizationWithRenewal(
		t, h, volume.Volume, peer, "stale-scope-epoch", []string{"write"}, "cloud-private-state:computer-1", 1,
	)
	if _, err := h.manager.IssueMount("stale-scope-epoch", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: staleToken, ClientCSRPEM: clientCSR,
		Access: []string{"write"}, AutomaticReauthorization: true,
	}); !errors.Is(err, ErrRenewalScopeFenced) {
		t.Fatalf("stale issuance = %v, want ErrRenewalScopeFenced", err)
	}

	*h.now = h.now.Add(time.Minute)
	if err := h.manager.HeartbeatCell(CellHeartbeat{
		CellID: cell.ID, PlanGeneration: cell.PlanGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.IssueMount("fenced-after-advance", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "fenced-after-advance", []string{"write"}, "cloud-private-state:computer-1", 2,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	}); !errors.Is(err, ErrRenewalScopeFenced) {
		t.Fatalf("issuance below advanced fence = %v, want ErrRenewalScopeFenced", err)
	}
}

func TestRenewalScopeTerminalizationIsIssuerScopedAndPreservesTerminals(t *testing.T) {
	state := NewState()
	state.MountEnrollments = map[string]MountEnrollment{
		"same-lower":  {ProductIssuer: "product-a", RenewalScope: "scope", RenewalEpoch: 1, State: MountEnrollmentActive},
		"same-equal":  {ProductIssuer: "product-a", RenewalScope: "scope", RenewalEpoch: 2, State: MountEnrollmentActive},
		"other-scope": {ProductIssuer: "product-a", RenewalScope: "other", RenewalEpoch: 1, State: MountEnrollmentActive},
		"other-issuer": {ProductIssuer: "product-b", RenewalScope: "scope", RenewalEpoch: 1,
			State: MountEnrollmentActive},
		"terminal": {ProductIssuer: "product-a", RenewalScope: "scope", RenewalEpoch: 1,
			State: MountEnrollmentClosed, TerminationReason: "first"},
	}
	if !revokeRenewalScopeEnrollmentsBeforeEpoch(&state, "product-a", "scope", 2, "superseded", 100) {
		t.Fatal("terminalization reported no change")
	}
	if enrollment := state.MountEnrollments["same-lower"]; enrollment.State != MountEnrollmentRevoked || enrollment.TerminationReason != "superseded" {
		t.Fatalf("same-issuer lower epoch = %+v", enrollment)
	}
	for _, id := range []string{"same-equal", "other-scope", "other-issuer"} {
		if enrollment := state.MountEnrollments[id]; enrollment.State != MountEnrollmentActive {
			t.Fatalf("untouched enrollment %s = %+v", id, enrollment)
		}
	}
	if enrollment := state.MountEnrollments["terminal"]; enrollment.State != MountEnrollmentClosed || enrollment.TerminationReason != "first" {
		t.Fatalf("terminal enrollment = %+v", enrollment)
	}
}

func TestStateRejectsTwoActiveEnrollmentsInOneRenewalScope(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	authorization, err := h.manager.IssueMount("duplicate-scope-state", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "duplicate-scope-state", []string{"write"}, "cloud-private-state:duplicate", 1,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var invalid State
	if err := h.store.View(func(state State) error {
		var err error
		invalid, err = cloneState(state)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	duplicate := invalid.MountEnrollments[authorization.EnrollmentID]
	duplicate.ID = newUUID()
	invalid.MountEnrollments[duplicate.ID] = duplicate
	if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate active renewal scope validation = %v, want ErrInvalid", err)
	}
}

func TestStateRenewalEpochBounds(t *testing.T) {
	tests := []struct {
		name  string
		epoch uint64
		valid bool
	}{
		{name: "zero", epoch: 0},
		{name: "one", epoch: 1, valid: true},
		{name: "max", epoch: productauth.MaxRenewalEpoch, valid: true},
		{name: "max-plus-one", epoch: productauth.MaxRenewalEpoch + 1},
		{name: "uint64-max", epoch: ^uint64(0)},
	}

	for _, test := range tests {
		t.Run("fence/"+test.name, func(t *testing.T) {
			state := NewState()
			state.RenewalFences[renewalFenceKey("opensteer", "cloud-private-state:clc_fence")] = test.epoch
			err := state.Validate()
			if test.valid && err != nil {
				t.Fatalf("Validate fence epoch %d: %v", test.epoch, err)
			}
			if !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate fence epoch %d = %v, want ErrInvalid", test.epoch, err)
			}
		})
	}

	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	scope := "cloud-private-state:clc_enrollment"
	authorization, err := h.manager.IssueMount("state-epoch-bounds", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "state-epoch-bounds", []string{"write"}, scope, 1,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var base State
	if err := h.store.View(func(state State) error {
		var cloneErr error
		base, cloneErr = cloneState(state)
		return cloneErr
	}); err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run("enrollment/"+test.name, func(t *testing.T) {
			state, err := cloneState(base)
			if err != nil {
				t.Fatal(err)
			}
			enrollment := state.MountEnrollments[authorization.EnrollmentID]
			enrollment.RenewalEpoch = test.epoch
			state.MountEnrollments[enrollment.ID] = enrollment
			fenceEpoch := test.epoch
			if fenceEpoch == 0 || fenceEpoch > productauth.MaxRenewalEpoch {
				fenceEpoch = productauth.MaxRenewalEpoch
			}
			state.RenewalFences[renewalFenceKey("opensteer", scope)] = fenceEpoch
			err = state.Validate()
			if test.valid && err != nil {
				t.Fatalf("Validate enrollment epoch %d: %v", test.epoch, err)
			}
			if !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate enrollment epoch %d = %v, want ErrInvalid", test.epoch, err)
			}
		})
	}
}

func TestRenewalFenceMapCapacity(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	if _, err := h.store.TransactNatural("seed-renewal-fence-capacity", h.now.Unix(), func(state *State) (any, bool, error) {
		if state.RenewalFences == nil {
			state.RenewalFences = make(map[string]uint64)
		}
		for index := 0; index < MaxRenewalFences; index++ {
			state.RenewalFences[renewalFenceKey("opensteer", fmt.Sprintf("scope-%d", index))] = 1
		}
		return RenewalFence{Scope: "scope-0", Epoch: 1}, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	existingKey := renewalFenceKey("opensteer", "scope-0")
	existing, err := h.manager.AdvanceRenewalFences("opensteer", AdvanceRenewalFencesRequest{
		Reason: "existing-scope", Fences: []RenewalFence{{Scope: "scope-0", Epoch: 2}},
	})
	if err != nil || len(existing.Fences) != 1 || existing.Fences[0].Epoch != 2 {
		t.Fatalf("existing fence at capacity = %+v, %v", existing, err)
	}
	sequence := h.store.sequence
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	if _, err := h.manager.IssueMount("new-scope-at-capacity", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "new-scope-at-capacity", []string{"write"}, "new-scope", 1,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	}); !errors.Is(err, ErrRenewalFenceCapacity) {
		t.Fatalf("issuance fence at capacity = %v, want ErrRenewalFenceCapacity", err)
	}
	if _, err := h.manager.AdvanceRenewalFences("opensteer", AdvanceRenewalFencesRequest{
		Reason: "new-scope", Fences: []RenewalFence{{Scope: "new-scope", Epoch: 1}},
	}); !errors.Is(err, ErrRenewalFenceCapacity) {
		t.Fatalf("batch fence at capacity = %v, want ErrRenewalFenceCapacity", err)
	}
	if h.store.sequence != sequence {
		t.Fatalf("capacity failures changed sequence = %d, want %d", h.store.sequence, sequence)
	}
	var invalid State
	if err := h.store.View(func(state State) error {
		invalid = state
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	invalid.RenewalFences[renewalFenceKey("opensteer", "new-scope")] = 1
	if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-capacity state validation = %v, want ErrInvalid", err)
	}
	if got := invalid.RenewalFences[existingKey]; got != 2 {
		t.Fatalf("existing fence high-water = %d, want 2", got)
	}
}

func TestRenewalFenceAtExactEpochLeavesActiveEnrollment(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	authorization, err := h.manager.IssueMount("exact-fence-epoch", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "exact-fence-epoch", []string{"write"}, "cloud-private-state:exact", 7,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	sequence := h.store.sequence
	result, err := h.manager.AdvanceRenewalFences("opensteer", AdvanceRenewalFencesRequest{
		Reason: "delayed-stop-fence", Fences: []RenewalFence{{Scope: "cloud-private-state:exact", Epoch: 7}},
	})
	if err != nil || len(result.Fences) != 1 || result.Fences[0].Epoch != 7 || h.store.sequence != sequence {
		t.Fatalf("exact fence = %+v, sequence=%d want=%d, err=%v", result, h.store.sequence, sequence, err)
	}
	if err := h.store.View(func(state State) error {
		enrollment := state.MountEnrollments[authorization.EnrollmentID]
		if enrollment.State != MountEnrollmentActive {
			t.Fatalf("exact-epoch enrollment = %+v", enrollment)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConvergentRevocationConcurrentCallsPreserveFirstDecision(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	authorization, err := h.manager.IssueMount("concurrent-enrollment", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorization(t, h, volume.Volume, peer, "concurrent-enrollment", []string{"write"}),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 16
	start := make(chan struct{})
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			result, err := h.manager.RevokeVolumeMountEnrollment(
				"opensteer", volume.ID, authorization.EnrollmentID,
				TerminateMountEnrollmentRequest{Reason: fmt.Sprintf("concurrent-reason-%d", index)},
			)
			if err == nil && result.Outcome != MountEnrollmentRevocationRevoked {
				err = fmt.Errorf("outcome = %s", result.Outcome)
			}
			results <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := h.store.View(func(state State) error {
		enrollment := state.MountEnrollments[authorization.EnrollmentID]
		if enrollment.State != MountEnrollmentRevoked || enrollment.TerminationReason == "" {
			t.Fatalf("concurrently revoked enrollment = %+v", enrollment)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClosedEnrollmentPrunesBeforeNextScopedGeneration(t *testing.T) {
	h := newManagerHarness(t)
	cell, volume := readyVolumeForMount(t, h)
	clientPublic, clientCSR := testCSR(t)
	peerSPKI, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(peerSPKI)
	first, err := h.manager.IssueMount("incident-epoch-1", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "incident-epoch-1", []string{"write"}, "cloud-private-state:incident", 1,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.CloseMountEnrollment("incident-close", first.EnrollmentID, TerminateMountEnrollmentRequest{Reason: "startup-rollback"}); err != nil {
		t.Fatal(err)
	}
	*h.now = h.now.Add(mountEnrollmentRetention + time.Second)
	if err := h.manager.HeartbeatCell(CellHeartbeat{
		CellID: cell.ID, PlanGeneration: cell.PlanGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	second, err := h.manager.IssueMount("incident-epoch-2", IssueMountRequest{
		VolumeID: volume.ID, ProductAuthorization: signedProductAuthorizationWithRenewal(
			t, h, volume.Volume, peer, "incident-epoch-2", []string{"write"}, "cloud-private-state:incident", 2,
		),
		ClientCSRPEM: clientCSR, Access: []string{"write"}, AutomaticReauthorization: true,
	})
	if err != nil || second.EnrollmentID == "" {
		t.Fatalf("next generation issuance = %+v, %v", second, err)
	}
	revocation, err := h.manager.RevokeVolumeMountEnrollment(
		"opensteer", volume.ID, first.EnrollmentID, TerminateMountEnrollmentRequest{Reason: "stale-cleanup"},
	)
	if err != nil || revocation.Outcome != MountEnrollmentRevocationAbsent {
		t.Fatalf("pruned enrollment revocation = %+v, %v", revocation, err)
	}
}

func TestManagerReleaseUpgradeAdvancesTheSignedPlanGeneration(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("register-release-upgrade", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "us-west-2a",
		AuthorityHost: "cell.example.test", AuthorityDNSZone: "cell.example.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct,
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

func TestCellPlanVersionRequiresDurableAgentAndHelperCapability(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("version-gate", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 100_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	if plan := verifiedPlan(t, h.manager, cell.ID, *h.now); plan.Version != cellplan.VersionV1 {
		t.Fatalf("unobserved plan version = %d", plan.Version)
	}
	for _, test := range []struct {
		name          string
		agent, helper []uint32
		want          uint32
	}{
		{name: "agent-only", agent: []uint32{1, 2}, helper: []uint32{1}, want: 1},
		{name: "both", agent: []uint32{1, 2}, helper: []uint32{1, 2}, want: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
			observed, err := h.manager.ObserveCell("version-"+test.name, CellObservation{CellID: cell.ID, PlanGeneration: plan.Generation,
				ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix(),
				PlanVersions: test.agent, HelperPlanVersions: test.helper, HelperStateVersions: []uint32{1, 2}})
			if err != nil {
				t.Fatal(err)
			}
			cell = observed
			if got := verifiedPlan(t, h.manager, cell.ID, *h.now).Version; got != test.want {
				t.Fatalf("plan version = %d, want %d", got, test.want)
			}
		})
	}
}

func TestObservationCannotSwapIsolationIdentity(t *testing.T) {
	h := newManagerHarness(t)
	cell, _ := h.manager.RegisterCell("register", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.test",
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000, Pool: PoolProduct,
	})
	prepareCellForAdmission(t, h, cell)
	volume, _ := h.manager.CreateVolume("create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	cell, err := h.manager.ObserveCell("bad-observation", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.Placement.ProjectID + 1,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
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
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000, Pool: PoolProduct,
	})
	prepareCellForAdmission(t, h, cell)
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
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000, Pool: PoolProduct,
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
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000, Pool: PoolProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
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
				VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.Placement.ProjectID, ServiceUID: volume.Placement.ServiceUID,
				ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort, Provisioned: true, AuthorityRunning: true,
				AuthorityCSRPEM: csrPEM,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	observe("initial-csr", plan.Generation, csr)
	first, _ := h.manager.GetVolume(volume.ID)
	if first.Placement.AuthorityCertificatePEM == "" || first.Placement.AuthorityCertExpires == 0 {
		t.Fatalf("initial authority identity = %+v", first.Volume)
	}
	*h.now = h.now.Add(17 * time.Hour)
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	observe("renew-csr", plan.Generation, csr)
	renewed, _ := h.manager.GetVolume(volume.ID)
	if renewed.AuthorityEpoch != first.AuthorityEpoch || renewed.Placement.AuthorityCSRPEM != csr ||
		renewed.Placement.AuthorityCertificatePEM == first.Placement.AuthorityCertificatePEM || renewed.Placement.AuthorityCertExpires <= first.Placement.AuthorityCertExpires {
		t.Fatalf("renewed authority identity = %+v, first expiry=%d", renewed.Volume, first.Placement.AuthorityCertExpires)
	}
}

func TestAuthorityCSRSwapWithinGenerationQuarantinesVolume(t *testing.T) {
	h := newManagerHarness(t)
	cell, _ := h.manager.RegisterCell("register", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a", AuthorityHost: "cell.test",
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000, Pool: PoolProduct,
	})
	prepareCellForAdmission(t, h, cell)
	volume, _ := h.manager.CreateVolume("create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	_, firstCSR := testCSR(t)
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	base := CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix(),
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: 1, ProjectID: volume.Placement.ProjectID, ServiceUID: volume.Placement.ServiceUID,
			ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort, Provisioned: true, AuthorityCSRPEM: firstCSR,
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
		AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000, Pool: PoolProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	volume, err := h.manager.CreateVolume("create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, csr := testCSR(t)
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	base := VolumeObservation{
		VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID,
		ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort, Provisioned: true,
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

func readyVolumeForMount(t *testing.T, h managerHarness) (Cell, VolumeView) {
	t.Helper()
	cell, err := h.manager.RegisterCell("ready-cell", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 200_000, Pool: PoolProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	volume, err := h.manager.CreateVolume("ready-volume", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 100_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, authorityCSR := testCSR(t)
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	cell, err = h.manager.ObserveCell("ready-csr", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		PlanVersions: []uint32{1, 2}, HelperPlanVersions: []uint32{1, 2}, HelperStateVersions: []uint32{1, 2},
		ArchiveConfigured: true,
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
			Provisioned: true, AuthorityCSRPEM: authorityCSR,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan = verifiedPlan(t, h.manager, cell.ID, *h.now)
	cell, err = h.manager.ObserveCell("ready-running", CellObservation{
		CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		PlanVersions: []uint32{1, 2}, HelperPlanVersions: []uint32{1, 2}, HelperStateVersions: []uint32{1, 2},
		ArchiveConfigured: true,
		Volumes: []VolumeObservation{{
			VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
			Provisioned: true, AuthorityRunning: true,
		}},
	})
	if err != nil || cell.Health != CellHealthy {
		t.Fatalf("ready cell = %+v, %v", cell, err)
	}
	volume, err = h.manager.GetVolume(volume.ID)
	if err != nil || volume.State != VolumeReady {
		t.Fatalf("ready volume = %+v, %v", volume, err)
	}
	return cell, volume
}

func prepareCellForAdmission(t *testing.T, h managerHarness, cell Cell) Cell {
	t.Helper()
	observed, err := h.manager.ObserveCell("admission-"+cell.ID, CellObservation{
		CellID: cell.ID, PlanGeneration: cell.PlanGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
		PlanVersions: []uint32{1, 2}, HelperPlanVersions: []uint32{1, 2}, HelperStateVersions: []uint32{1, 2},
		ArchiveConfigured: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if observed.PlanGeneration != cell.PlanGeneration {
		observed, err = h.manager.ObserveCell("admission-v2-"+cell.ID, CellObservation{
			CellID: cell.ID, PlanGeneration: observed.PlanGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(),
			AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
			PlanVersions: []uint32{1, 2}, HelperPlanVersions: []uint32{1, 2}, HelperStateVersions: []uint32{1, 2},
			ArchiveConfigured: true,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return observed
}

func signedProductAuthorization(t *testing.T, h managerHarness, volume Volume, peer [32]byte, nonce string, access []string) string {
	t.Helper()
	return signedProductAuthorizationWithRenewal(t, h, volume, peer, nonce, access, "", 0)
}

func signedProductAuthorizationWithRenewal(t *testing.T, h managerHarness, volume Volume, peer [32]byte, nonce string, access []string, scope string, epoch uint64) string {
	t.Helper()
	token, err := productauth.Sign(h.productKey, productauth.Claims{
		Issuer: volume.ProductIssuer, Audience: "portablefs-manager", AuthorizationDomain: volume.AuthorizationDomain,
		Owner: volume.Owner, Subject: "agent-session", VolumeID: volume.ID, Access: access,
		PeerSPKI: base64.RawURLEncoding.EncodeToString(peer[:]), Nonce: nonce,
		NotBefore: h.now.Add(-time.Second).Unix(), Expires: h.now.Add(12 * time.Minute).Unix(),
		RenewalScope: scope, RenewalEpoch: epoch,
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
