package cellhelper

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

type fakeHost struct {
	absent   bool
	calls    []cellplan.VolumePlan
	observes []cellplan.VolumePlan
}

func (host *fakeHost) Observe(_ context.Context, plan cellplan.VolumePlan, _ Assignment) controlplane.VolumeObservation {
	host.observes = append(host.observes, plan)
	return controlplane.VolumeObservation{
		Provisioned: plan.Phase != cellplan.PhaseRetire, AuthorityRunning: plan.Phase == cellplan.PhaseServe,
		AuthorityAbsent: plan.Phase == cellplan.PhaseFence && host.absent,
	}
}

func (host *fakeHost) Apply(_ context.Context, plan cellplan.VolumePlan, _ Assignment) controlplane.VolumeObservation {
	host.calls = append(host.calls, plan)
	return controlplane.VolumeObservation{
		Provisioned: plan.Phase != cellplan.PhaseRetire, AuthorityRunning: plan.Phase == cellplan.PhaseServe,
		AuthorityAbsent: plan.Phase == cellplan.PhaseFence && host.absent,
	}
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

func helperPlan(now time.Time, cellID string, generation, authorityGeneration uint64, phase cellplan.VolumePhase) cellplan.Plan {
	certificate := ""
	if phase == cellplan.PhaseServe {
		certificate = "cert"
	}
	return cellplan.Plan{
		Version: cellplan.Version, CellID: cellID, Generation: generation,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), ReleaseID: "release",
		Volumes: []cellplan.VolumePlan{{
			VolumeID: "22222222-2222-4222-8222-222222222222", Phase: phase,
			AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "product", ProductPublicKeyPEM: "product-key",
			AuthorityID: "authority", AuthorityGeneration: authorityGeneration, ProjectID: 10001,
			ServiceUID: 200001, ServiceGID: 200001, ListenPort: 20001, QuotaBytes: 1 << 30, QuotaInodes: 1000,
			AuthorityServerName: "volume.test", AuthorityCertificate: certificate, AuthorityCAPEM: "authority-ca",
			ClientCAPEM: "client-ca", CapabilityPublicKey: "cap-key",
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
