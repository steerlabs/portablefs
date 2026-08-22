package cellhelper

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

type fakeHost struct {
	absent            bool
	archiveConfigured bool
	calls             []cellplan.VolumePlan
	observes          []cellplan.VolumePlan
}

func (host *fakeHost) ArchiveConfigured() bool { return host.archiveConfigured }

type scriptedHost struct {
	archiveConfigured bool
	applies           []struct {
		observation controlplane.VolumeObservation
		update      HostUpdate
	}
	observes []struct {
		observation controlplane.VolumeObservation
		update      HostUpdate
	}
}

func (host *scriptedHost) ArchiveConfigured() bool { return host.archiveConfigured }

func (host *scriptedHost) Apply(_ context.Context, _ cellplan.VolumePlan, _ Assignment) (controlplane.VolumeObservation, HostUpdate) {
	if len(host.applies) == 0 {
		return controlplane.VolumeObservation{Error: "unexpected apply"}, HostUpdate{}
	}
	next := host.applies[0]
	host.applies = host.applies[1:]
	return next.observation, next.update
}

func (host *scriptedHost) Observe(_ context.Context, _ cellplan.VolumePlan, _ Assignment) (controlplane.VolumeObservation, HostUpdate) {
	if len(host.observes) == 0 {
		return controlplane.VolumeObservation{Error: "unexpected observe"}, HostUpdate{}
	}
	next := host.observes[0]
	host.observes = host.observes[1:]
	return next.observation, next.update
}

func (host *fakeHost) Observe(_ context.Context, plan cellplan.VolumePlan, _ Assignment) (controlplane.VolumeObservation, HostUpdate) {
	host.observes = append(host.observes, plan)
	return controlplane.VolumeObservation{
		Provisioned: true, AuthorityRunning: plan.Phase == cellplan.PhaseServe,
		AuthorityAbsent: plan.Phase == cellplan.PhaseFence && host.absent,
	}, HostUpdate{}
}

func (host *fakeHost) Apply(_ context.Context, plan cellplan.VolumePlan, _ Assignment) (controlplane.VolumeObservation, HostUpdate) {
	host.calls = append(host.calls, plan)
	return controlplane.VolumeObservation{
		Provisioned: true, AuthorityRunning: plan.Phase == cellplan.PhaseServe,
		AuthorityAbsent: plan.Phase == cellplan.PhaseFence && host.absent,
	}, HostUpdate{}
}

func TestReconcilerRequiresFenceBeforeAuthorityGeneration(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	host := &fakeHost{}
	reconciler := &Reconciler{
		CellID: "11111111-1111-4111-8111-111111111111", PlanPublicKey: publicKey,
		ClockSkew: 10 * time.Second, PlanLifetime: 5 * time.Minute, Now: func() time.Time { return now },
		StatePath: filepath.Join(t.TempDir(), "state"), Host: host, ReleaseID: "helper-test",
	}
	plan := helperPlan(now, reconciler.CellID, 1, 1, cellplan.PhaseServe)
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err != nil {
		t.Fatal(err)
	}
	if len(host.calls) != 1 || len(host.observes) != 1 {
		t.Fatalf("unchanged plan applied=%d observed=%d", len(host.calls), len(host.observes))
	}
	plan.Generation++
	plan.IssuedAt++
	plan.ExpiresAt++
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err != nil {
		t.Fatal(err)
	}
	if len(host.calls) != 1 || len(host.observes) != 2 {
		t.Fatalf("envelope-only refresh applied=%d observed=%d", len(host.calls), len(host.observes))
	}
	plan.Generation++
	plan.IssuedAt++
	plan.ExpiresAt++
	plan.Volumes[0].AuthorityGeneration = 2
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err == nil {
		t.Fatal("replacement authority started without a local absence proof")
	}

	plan.Volumes[0].AuthorityGeneration = 1
	plan.Volumes[0].Phase = cellplan.PhaseFence
	host.absent = true
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err != nil {
		t.Fatal(err)
	}
	plan.Generation++
	plan.IssuedAt++
	plan.ExpiresAt++
	plan.Volumes[0].AuthorityGeneration = 2
	plan.Volumes[0].Phase = cellplan.PhaseProvision
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err != nil {
		t.Fatalf("replacement after local fence = %v", err)
	}
}

func TestReconcilerReappliesUnchangedPlanForNewHelperRelease(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	host := &fakeHost{}
	statePath := filepath.Join(t.TempDir(), "state")
	reconciler := &Reconciler{
		CellID: "11111111-1111-4111-8111-111111111111", PlanPublicKey: publicKey,
		ClockSkew: 10 * time.Second, PlanLifetime: 5 * time.Minute, Now: func() time.Time { return now },
		StatePath: statePath, Host: host, ReleaseID: "helper-one",
	}
	plan := helperPlan(now, reconciler.CellID, 1, 1, cellplan.PhaseServe)
	envelope := signedHelperPlan(t, privateKey, plan)
	if _, err := reconciler.Reconcile(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if len(host.calls) != 1 || len(host.observes) != 0 {
		t.Fatalf("initial apply=%d observe=%d", len(host.calls), len(host.observes))
	}
	reconciler.ReleaseID = "helper-two"
	if _, err := reconciler.Reconcile(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if len(host.calls) != 2 || len(host.observes) != 0 {
		t.Fatalf("release migration apply=%d observe=%d", len(host.calls), len(host.observes))
	}
	if _, err := reconciler.Reconcile(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if len(host.calls) != 2 || len(host.observes) != 1 {
		t.Fatalf("settled release apply=%d observe=%d", len(host.calls), len(host.observes))
	}
}

func TestReconcilerRejectsSameGenerationEquivocationAndIDSwap(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	reconciler := &Reconciler{
		CellID: "11111111-1111-4111-8111-111111111111", PlanPublicKey: publicKey,
		ClockSkew: 10 * time.Second, PlanLifetime: 5 * time.Minute, Now: func() time.Time { return now },
		StatePath: filepath.Join(t.TempDir(), "state"), Host: &fakeHost{}, ReleaseID: "helper-test",
	}
	plan := helperPlan(now, reconciler.CellID, 1, 1, cellplan.PhaseProvision)
	envelope := signedHelperPlan(t, privateKey, plan)
	if _, err := reconciler.Reconcile(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	equivocated := plan
	equivocated.ReleaseID = "different"
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, equivocated)); err == nil {
		t.Fatal("same generation accepted a different signed payload")
	}
	plan.Generation++
	plan.IssuedAt++
	plan.ExpiresAt++
	plan.Volumes[0].ProjectID++
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err == nil {
		t.Fatalf("immutable project ID swap = %v", err)
	}
}

func TestStateRejectsUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cellID := "11111111-1111-4111-8111-111111111111"
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(path, cellID); err == nil {
		t.Fatal("cellhelper accepted unsupported state version 1")
	}
}

func TestArchiveStateMachinePersistsNonceAndSeal(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	seal := &controlplane.ArchiveSealedObservation{Attempt: "33333333-3333-4333-8333-333333333333",
		Manifest: controlplane.ObjectRef{Key: "manifest", SizeBytes: 1, SHA256: strings64("a")},
		Packs:    []controlplane.ObjectRef{{Key: "pack", SizeBytes: 1, SHA256: strings64("b")}}, RootDigest: strings64("c"),
		SealedAllocatedBytes: 4096, SealedInodes: 1, FormatVersion: 1, ChunkSizeBytes: 8 << 20, KeyVersion: "default"}
	host := &scriptedHost{applies: []struct {
		observation controlplane.VolumeObservation
		update      HostUpdate
	}{
		{controlplane.VolumeObservation{Provisioned: true, AuthorityRunning: true}, HostUpdate{LastQuiesceNonce: strings64("a")}},
		{controlplane.VolumeObservation{Provisioned: true, AuthorityAbsent: true, QuiesceProven: true}, HostUpdate{}},
		{controlplane.VolumeObservation{Provisioned: true, AuthorityAbsent: true, QuiesceProven: true, ArchiveSealed: seal}, HostUpdate{ArchiveSealed: seal}},
	}}
	reconciler := testReconciler(t, publicKey, now, host)
	plan := helperPlan(now, reconciler.CellID, 1, 1, cellplan.PhaseArchive)
	plan.Volumes[0].ArchiveTo = &cellplan.ArchiveTarget{Attempt: seal.Attempt, KeyVersion: "default"}
	for pass := 0; pass < 3; pass++ {
		if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}
	state, err := loadState(reconciler.StatePath, reconciler.CellID)
	if err != nil {
		t.Fatal(err)
	}
	assignment := state.Assignments[plan.Volumes[0].VolumeID]
	if assignment.LastQuiesceNonce != strings64("a") || assignment.ArchiveSealed == nil || assignment.ArchiveSealed.Attempt != seal.Attempt {
		t.Fatalf("durable archive state = %+v", assignment)
	}
}

func TestDestroyReleaseWritesExactTombstoneAndLeavingPlanIsSafe(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	base := helperPlan(now, "11111111-1111-4111-8111-111111111111", 1, 1, cellplan.PhaseDestroy)
	assignment := assignmentFromPlan(base.Volumes[0], base.CellID)
	record := completeDestroyRecord(assignment)
	payload, _ := json.Marshal(record)
	digest := sha256.Sum256(payload)
	proof := &DestroyProof{Record: record, SHA256: hex.EncodeToString(digest[:])}
	host := &scriptedHost{applies: []struct {
		observation controlplane.VolumeObservation
		update      HostUpdate
	}{{controlplane.VolumeObservation{AuthorityAbsent: true, DestroyProofSHA256: proof.SHA256}, HostUpdate{DestroyProof: proof}}}}
	reconciler := testReconciler(t, publicKey, now, host)
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, base)); err != nil {
		t.Fatal(err)
	}
	release := base
	release.Generation = 2
	release.Volumes[0].Phase = cellplan.PhaseRelease
	release.Volumes[0].ReleaseProof = &cellplan.ReleaseProof{PlacementSequence: 1, AuthorityEpoch: 1, DestroyProofSHA256: proof.SHA256}
	observation, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, release))
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Volumes) != 1 || !observation.Volumes[0].Released {
		t.Fatalf("release observation = %+v", observation.Volumes)
	}
	state, err := loadState(reconciler.StatePath, reconciler.CellID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Assignments) != 0 || state.Tombstones[assignment.VolumeID].DestroyProofSHA256 != proof.SHA256 {
		t.Fatalf("released state = %+v", state)
	}
	empty := release
	empty.Generation = 3
	empty.Volumes = nil
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, empty)); err != nil {
		t.Fatalf("tombstoned volume could not leave plan: %v", err)
	}
}

func TestReleaseMismatchAborts(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	plan := helperPlan(now, "11111111-1111-4111-8111-111111111111", 1, 1, cellplan.PhaseRelease)
	plan.Volumes[0].ReleaseProof = &cellplan.ReleaseProof{PlacementSequence: 1, AuthorityEpoch: 1, DestroyProofSHA256: strings64("f")}
	reconciler := testReconciler(t, publicKey, now, &scriptedHost{})
	if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err == nil {
		t.Fatal("release without an exact assignment or tombstone was accepted")
	}
}

func TestRestoreProgressAndUsagePassThrough(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	host := &scriptedHost{applies: []struct {
		observation controlplane.VolumeObservation
		update      HostUpdate
	}{{controlplane.VolumeObservation{Provisioned: true, AuthorityAbsent: true, UsedBytes: 12, UsedInodes: 3}, HostUpdate{}},
		{controlplane.VolumeObservation{Provisioned: true, AuthorityRunning: true, RestoreNamespaceReady: true, UsedBytes: 20, UsedInodes: 4}, HostUpdate{}}},
		observes: []struct {
			observation controlplane.VolumeObservation
			update      HostUpdate
		}{{controlplane.VolumeObservation{Provisioned: true, AuthorityRunning: true, RestoreNamespaceReady: true,
			RestoreProgressPermille: 750, RestoreState: "blocked", UsedBytes: 30, UsedInodes: 5}, HostUpdate{}}}}
	reconciler := testReconciler(t, publicKey, now, host)
	plan := helperPlan(now, reconciler.CellID, 1, 1, cellplan.PhaseRestore)
	plan.Volumes[0].AuthorityCertificate = "certificate"
	plan.Volumes[0].RestoreFrom = testRestoreSource()
	for pass := 0; pass < 2; pass++ {
		if _, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan)); err != nil {
			t.Fatal(err)
		}
	}
	observation, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan))
	if err != nil {
		t.Fatal(err)
	}
	got := observation.Volumes[0]
	if got.RestoreProgressPermille != 750 || got.RestoreState != "blocked" || got.UsedBytes != 30 || got.UsedInodes != 5 {
		t.Fatalf("restore observation = %+v", got)
	}
}

func testReconciler(t *testing.T, publicKey ed25519.PublicKey, now time.Time, host Host) *Reconciler {
	t.Helper()
	return &Reconciler{CellID: "11111111-1111-4111-8111-111111111111", PlanPublicKey: publicKey,
		ClockSkew: 10 * time.Second, PlanLifetime: 5 * time.Minute, Now: func() time.Time { return now },
		StatePath: filepath.Join(t.TempDir(), "state"), Host: host, ReleaseID: "helper-test"}
}

func testRestoreSource() *cellplan.RestoreSource {
	return &cellplan.RestoreSource{SealedEpoch: 1, Attempt: "33333333-3333-4333-8333-333333333333",
		ManifestDigestSHA256: strings64("a"), ManifestSizeBytes: 1, PackCount: 1, SealedAllocatedBytes: 1, SealedInodes: 1}
}

func completeDestroyRecord(assignment Assignment) DestroyRecord {
	return DestroyRecord{AuthorityEpoch: assignment.AuthorityGeneration, AuthorityID: assignment.AuthorityID,
		AuthorityServerName: assignment.AuthorityServerName, CellID: assignment.CellID, ListenPort: assignment.ListenPort,
		PlacementSequence: assignment.PlacementSequence, Postconditions: DestroyPostconditions{ConfigRootAbsent: true,
			DropInsAbsent: true, QuotaCleared: true, StateRootAbsent: true, SysusersConfAbsent: true, TreeAbsent: true},
		ProjectID: assignment.ProjectID, ServiceGID: assignment.ServiceGID, ServiceUID: assignment.ServiceUID, VolumeID: assignment.VolumeID}
}

func strings64(character string) string {
	result := ""
	for len(result) < 64 {
		result += character
	}
	return result[:64]
}

func helperPlan(now time.Time, cellID string, generation, authorityGeneration uint64, phase cellplan.VolumePhase) cellplan.Plan {
	certificate := ""
	if phase == cellplan.PhaseServe {
		certificate = "cert"
	}
	return cellplan.Plan{
		Version: cellplan.Version, CellID: cellID, Generation: generation,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), ReleaseID: "release",
		UsageRefreshSeconds: 300,
		AuthorityCAPEM:      "authority-ca", ClientCAPEM: "client-ca", CapabilityPublicKey: "cap-key",
		Volumes: []cellplan.VolumePlan{{
			VolumeID: "22222222-2222-4222-8222-222222222222", Phase: phase,
			AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "product", ProductPublicKeyPEM: "product-key",
			AuthorityID: "authority", AuthorityGeneration: authorityGeneration, ProjectID: 10001,
			ServiceUID: 200001, ServiceGID: 200001, ListenPort: 20001, QuotaBytes: 1 << 30, QuotaInodes: 1000,
			AuthorityServerName: "volume.test", AuthorityCertificate: certificate, PlacementSequence: 1,
		}},
	}
}

func signedHelperPlan(t *testing.T, key ed25519.PrivateKey, plan cellplan.Plan) cellplan.Envelope {
	t.Helper()
	envelope, err := cellplan.Sign(key, plan)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

// The archive capability is a live per-pass fact, not a durable one: the helper
// answers it on every observation so credentials appearing or being revoked
// reach the Manager on the next poll.
func TestReconcilerReportsHostArchiveCapabilityEveryPass(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	host := &fakeHost{archiveConfigured: true}
	reconciler := &Reconciler{
		CellID: "11111111-1111-4111-8111-111111111111", PlanPublicKey: publicKey,
		ClockSkew: 10 * time.Second, PlanLifetime: 5 * time.Minute, Now: func() time.Time { return now },
		StatePath: filepath.Join(t.TempDir(), "state"), Host: host, ReleaseID: "helper-test",
	}
	plan := helperPlan(now, reconciler.CellID, 1, 1, cellplan.PhaseServe)
	observation, err := reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan))
	if err != nil || !observation.ArchiveConfigured {
		t.Fatalf("configured helper observation = %+v, %v", observation, err)
	}
	host.archiveConfigured = false
	observation, err = reconciler.Reconcile(context.Background(), signedHelperPlan(t, privateKey, plan))
	if err != nil || observation.ArchiveConfigured {
		t.Fatalf("revoked helper observation = %+v, %v", observation, err)
	}
}
