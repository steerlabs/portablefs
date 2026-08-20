package controlplane

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPlacementAdmissionUsesPendingChargesAndStaleUsageFailsClosed(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.ProvisionFloorBytes = 700 << 20
	h.manager.cfg.ProvisionFloorInodes = 1000
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("capacity-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 1500 << 20, CapacityInodes: 100_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	first, err := h.manager.CreateVolume("capacity-first", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 4 << 30, QuotaInodes: 50_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	observeTieredVolume(t, h, cell.ID, "capacity-usage", VolumeObservation{VolumeID: first.ID, AuthorityGeneration: first.AuthorityEpoch,
		ProjectID: first.Placement.ProjectID, ServiceUID: first.Placement.ServiceUID, ServiceGID: first.Placement.ServiceGID,
		ListenPort: first.Placement.ListenPort, Provisioned: true})
	if _, err := h.manager.CreateVolume("capacity-second", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 4 << 30, QuotaInodes: 50_000, Pool: PoolProduct}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("double admission = %v", err)
	}
	if got, _ := h.manager.GetVolume(first.ID); got.Placement.PendingBytes != 700<<20 {
		t.Fatalf("pending charge = %d", got.Placement.PendingBytes)
	}

	*h.now = h.now.Add(6 * time.Minute)
	current, _ := h.manager.GetVolume(first.ID)
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: current.Placement.CellID, PlanGeneration: verifiedPlan(t, h.manager, cell.ID, *h.now).Generation,
		ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent", HelperReleaseID: "helper", ObservedUnix: h.now.Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.CreateVolume("stale-usage", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 1000, Pool: PoolProduct}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("stale usage admission = %v", err)
	}
}

func TestPoolIsolationDecommissionCapacityRaiseAndReport(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("system-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 4 << 30, CapacityInodes: 100_000, Pool: PoolSystem})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	if _, err := h.manager.CreateVolume("wrong-pool", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 1000, Pool: PoolProduct}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("pool isolation = %v", err)
	}
	if _, err := h.manager.UpdateCellCapacity("lower", cell.ID, UpdateCellCapacityRequest{CapacityBytes: 3 << 30, CapacityInodes: 100_000}); !errors.Is(err, ErrConflict) {
		t.Fatalf("capacity lower = %v", err)
	}
	raised, err := h.manager.UpdateCellCapacity("raise", cell.ID, UpdateCellCapacityRequest{CapacityBytes: 5 << 30, CapacityInodes: 110_000})
	if err != nil || raised.CapacityBytes != 5<<30 || raised.CapacityInodes != 110_000 {
		t.Fatalf("capacity raise = %+v, %v", raised, err)
	}
	if _, err := h.manager.UpdateCellCapacity("raise", "22222222-2222-4222-8222-222222222222",
		UpdateCellCapacityRequest{CapacityBytes: 5 << 30, CapacityInodes: 110_000}); !errors.Is(err, ErrIdempotencyReuse) {
		t.Fatalf("cell path was not bound into idempotency key = %v", err)
	}
	if _, err := h.manager.DecommissionCell("decommission", cell.ID, DecommissionCellRequest{Reason: "drain"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.CreateVolume("decommissioned", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 1000, Pool: PoolSystem}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("decommission admission = %v", err)
	}
	report, err := h.manager.Capacity()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Pools) != 3 || report.Pools[1].Pool != PoolSystem || report.Pools[1].CapacityBytes != 5<<30 || report.Pools[1].CreateAdmissible {
		t.Fatalf("capacity report = %+v", report)
	}
}

func TestRestorePriorityUsesWakeBurstHeadroom(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1500 << 20
	cell, err := h.manager.RegisterCell("priority-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 100_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	volume, err := h.manager.CreateVolume("priority-first", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 10_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	*h.now = h.now.Add(time.Second)
	observeTieredVolume(t, h, cell.ID, "priority-usage", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch,
		ProjectID: volume.Placement.ProjectID, ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID,
		ListenPort: volume.Placement.ListenPort, Provisioned: true, UsedBytes: 500 << 20, UsedInodes: 100})
	var state State
	if err := h.store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.admitPlacement(&state, PoolProduct, 64<<20, 1024, false, h.now.Unix()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("create under wake envelope = %v", err)
	}
	if _, err := h.manager.admitPlacement(&state, PoolProduct, 64<<20, 1024, true, h.now.Unix()); err != nil {
		t.Fatalf("restore under wake envelope = %v", err)
	}
}

func TestAbandonmentForceClearsOnlyVerifiedArchivesAndCellIDIsPermanent(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.ArchiveVerifier = &fakeArchiveVerifier{}
	cell, volume := readyVolumeForMount(t, h)
	archiving, err := h.manager.ArchiveVolume("abandon-archive", ArchiveVolumeRequest{VolumeID: volume.ID})
	if err != nil {
		t.Fatal(err)
	}
	observeTieredVolume(t, h, cell.ID, "abandon-quiesce", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: archiving.AuthorityEpoch,
		ProjectID: archiving.Placement.ProjectID, ServiceUID: archiving.Placement.ServiceUID, ServiceGID: archiving.Placement.ServiceGID,
		ListenPort: archiving.Placement.ListenPort, AuthorityAbsent: true, QuiesceProven: true})
	exporting, _ := h.manager.GetVolume(volume.ID)
	seal := validArchiveSeal(exporting.ArchiveAttempt)
	observeTieredVolume(t, h, cell.ID, "abandon-seal", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: exporting.AuthorityEpoch,
		ProjectID: exporting.Placement.ProjectID, ServiceUID: exporting.Placement.ServiceUID, ServiceGID: exporting.Placement.ServiceGID,
		ListenPort: exporting.Placement.ListenPort, AuthorityAbsent: true, ArchiveSealed: &seal})
	if err := h.manager.NoteVerify(volume.ID); err != nil {
		t.Fatal(err)
	}
	plan := verifiedPlan(t, h.manager, cell.ID, *h.now)
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: cell.ID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-v2", HelperReleaseID: "helper-v2", ObservedUnix: h.now.Unix()}); err != nil {
		t.Fatal(err)
	}
	active, err := h.manager.CreateVolume("abandon-active", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 1000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	abandoned, err := h.manager.AbandonCell("abandon", cell.ID, AbandonCellRequest{Reason: "lost AZ"})
	if err != nil || !abandoned.Abandoned {
		t.Fatalf("AbandonCell = %+v, %v", abandoned, err)
	}
	archived, _ := h.manager.GetVolume(volume.ID)
	if archived.State != VolumeArchived || archived.Placement != nil || archived.ArchiveCycleStep != "released" {
		t.Fatalf("abandoned archive = %+v", archived)
	}
	if lost, _ := h.manager.GetVolume(active.ID); lost.State != VolumeQuarantined || !strings.Contains(lost.QuarantineReason, "cell abandoned") {
		t.Fatalf("abandoned active placement = %+v", lost)
	}
	if err := h.store.View(func(state State) error {
		if len(state.OrphanedPlacements) != 1 || state.OrphanedPlacements[0].VolumeID != volume.ID {
			t.Fatalf("orphans = %+v", state.OrphanedPlacements)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.RegisterCell("reuse-abandoned", RegisterCellRequest{ID: cell.ID, AvailabilityZone: "zone-a", AuthorityHost: "new.test",
		AuthorityDNSZone: "new.test", CapacityBytes: 1 << 30, CapacityInodes: 1000, Pool: PoolProduct}); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("abandoned re-register = %v", err)
	}
	if _, err := h.manager.CreateVolume("abandoned-admission", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 1000, Pool: PoolProduct}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("abandoned cell admission = %v", err)
	}
}
