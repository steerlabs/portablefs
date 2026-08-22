package controlplane

import (
	"errors"
	"fmt"
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

// A cell heartbeat stays fresh while one placement's own measurement freezes —
// a host measurement failure is exactly that shape. The frozen placement must
// then be charged its quota ceiling, not the reading nobody is refreshing.
func TestStalePerPlacementUsageIsChargedAtQuota(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("stale-placement-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111",
		AvailabilityZone: "zone-a", AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 3 << 30, CapacityInodes: 100_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	volume, err := h.manager.CreateVolume("stale-placement-volume", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner",
		ProductIssuer: "opensteer", QuotaBytes: 2 << 30, QuotaInodes: 50_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	identity := VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID,
		ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort}
	*h.now = h.now.Add(time.Second)
	measured := identity
	measured.Provisioned, measured.UsedBytes, measured.UsedInodes = true, 1<<20, 16
	observeTieredVolume(t, h, cell.ID, "stale-placement-measured", measured)
	if _, err := h.manager.admitPlacement(currentState(t, h), PoolProduct, 2<<30, 1024, false, h.now.Unix()); err != nil {
		t.Fatalf("admission against a freshly measured placement = %v", err)
	}

	*h.now = h.now.Add(6 * time.Minute)
	failed := identity
	failed.Error = "xfs_quota is unavailable"
	observeTieredVolume(t, h, cell.ID, "stale-placement-host-error", failed)
	frozen, _ := h.manager.GetVolume(volume.ID)
	if frozen.Placement.UsedBytes != 1<<20 || h.now.Unix()-frozen.Placement.UsedObservedUnix <= int64(h.manager.cfg.UsageStaleAfter/time.Second) {
		t.Fatalf("placement measurement was not left stale = %+v", frozen.Placement)
	}
	if fresh := currentState(t, h).Cells[cell.ID]; h.now.Unix()-fresh.LastObservedUnix > int64(h.manager.cfg.UsageStaleAfter/time.Second) {
		t.Fatalf("cell observation went stale too, so the test proves nothing = %+v", fresh)
	}
	if _, err := h.manager.admitPlacement(currentState(t, h), PoolProduct, 2<<30, 1024, false, h.now.Unix()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("admission against a stale placement = %v", err)
	}
}

func TestPeriodicUnchangedObservationsKeepIdleCellAdmissible(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("idle-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111",
		AvailabilityZone: "zone-a", AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 40 << 30, CapacityInodes: 2_000_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	var observations []VolumeObservation
	for index := range 2 {
		volume, err := h.manager.CreateVolume(fmt.Sprintf("idle-volume-%d", index), CreateVolumeRequest{
			AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
			QuotaBytes: 10 << 30, QuotaInodes: 1_000_000, Pool: PoolProduct,
		})
		if err != nil {
			t.Fatal(err)
		}
		observations = append(observations, VolumeObservation{
			VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
			UsedBytes: 26 << 20, UsedInodes: 987,
		})
		observeTieredCell(t, h, cell.ID, fmt.Sprintf("idle-created-%d", index), true, observations...)
	}
	for refresh := range 8 {
		*h.now = h.now.Add(90 * time.Second)
		observeTieredCell(t, h, cell.ID, fmt.Sprintf("idle-refresh-%d", refresh), true, observations...)
	}
	report, err := h.manager.Capacity()
	if err != nil || !report.Pools[0].CreateAdmissible {
		t.Fatalf("capacity after periodic unchanged observations = %+v, %v", report, err)
	}
	for _, volume := range currentState(t, h).Volumes {
		if h.now.Unix()-volume.Placement.UsedObservedUnix > int64(h.manager.cfg.UsageStaleAfter/time.Second) {
			t.Fatalf("periodic observation left stale usage = %+v", volume.Placement)
		}
	}
}

// Restore work requires a cell whose helper can hydrate; creates never do.
func TestRestoreAdmissionRequiresAnArchiveCapableCell(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("restore-capability-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111",
		AvailabilityZone: "zone-a", AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	if _, err := h.manager.admitPlacement(currentState(t, h), PoolProduct, 64<<20, 1024, true, h.now.Unix()); err != nil {
		t.Fatalf("restore onto an archive-capable cell = %v", err)
	}
	observeTieredCell(t, h, cell.ID, "restore-capability-lost", false)
	if _, err := h.manager.admitPlacement(currentState(t, h), PoolProduct, 64<<20, 1024, true, h.now.Unix()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("restore onto an archive-incapable cell = %v", err)
	}
	if _, err := h.manager.admitPlacement(currentState(t, h), PoolProduct, 64<<20, 1024, false, h.now.Unix()); err != nil {
		t.Fatalf("create onto an archive-incapable cell = %v", err)
	}
	report, err := h.manager.Capacity()
	if err != nil || report.Pools[0].Pool != PoolProduct || !report.Pools[0].CreateAdmissible || report.Pools[0].RestoreAdmissible {
		t.Fatalf("capacity report = %+v, %v", report, err)
	}
}

// Busy and full are different answers: a saturated cell is retryable unchanged,
// an undersized fleet is not.
func TestRestoreConcurrencyCapIsBusyNotCapacity(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.MaxRestoringPerCell = 2
	cell, err := h.manager.RegisterCell("restore-cap-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111",
		AvailabilityZone: "zone-a", AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	state := currentState(t, h)
	if _, err := h.manager.admitPlacement(state, PoolProduct, 64<<20, 1024, true, h.now.Unix()); err != nil {
		t.Fatalf("restore under the cap = %v", err)
	}
	for index := range h.manager.cfg.MaxRestoringPerCell {
		id := fmt.Sprintf("restoring-%d", index)
		state.Volumes[id] = Volume{ID: id, Pool: PoolProduct, State: VolumeRestoring,
			Placement: &Placement{CellID: cell.ID, CreatedUnix: h.now.Unix(), UsedObservedUnix: h.now.Unix()}}
	}
	if _, err := h.manager.admitPlacement(state, PoolProduct, 64<<20, 1024, true, h.now.Unix()); !errors.Is(err, ErrBusy) {
		t.Fatalf("restore at the cap = %v", err)
	}
	// The cap is per-cell restore concurrency only; creates share nothing with it.
	if _, err := h.manager.admitPlacement(state, PoolProduct, 64<<20, 1024, false, h.now.Unix()); err != nil {
		t.Fatalf("create beside saturated restores = %v", err)
	}
	// A cell that could not hold the placement at any concurrency never reaches
	// the busy check, so the caller still learns the fleet is too small.
	if _, err := h.manager.admitPlacement(state, PoolProduct, 1<<62, 1024, true, h.now.Unix()); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversized restore = %v", err)
	}
}

// Each archive cycle runs a full-tree exporter beside live authorities, so a
// cell admits a bounded number at a time. Only the cursors that still burden
// the cell count.
func TestPerCellArchiveConcurrencyCapRefusesRetryablyWithoutStateChange(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.ArchiveVerifier = &fakeArchiveVerifier{}
	h.manager.cfg.MaxArchivingPerCell = 1
	cell, first := readyVolumeForMount(t, h)
	second, err := h.manager.CreateVolume("archive-cap-second-volume", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner",
		ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 10_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	_, authorityCSR := testCSR(t)
	firstServing := VolumeObservation{VolumeID: first.ID, AuthorityGeneration: first.AuthorityEpoch, ProjectID: first.Placement.ProjectID,
		ServiceUID: first.Placement.ServiceUID, ServiceGID: first.Placement.ServiceGID, ListenPort: first.Placement.ListenPort,
		Provisioned: true, AuthorityRunning: true}
	secondServing := VolumeObservation{VolumeID: second.ID, AuthorityGeneration: second.AuthorityEpoch, ProjectID: second.Placement.ProjectID,
		ServiceUID: second.Placement.ServiceUID, ServiceGID: second.Placement.ServiceGID, ListenPort: second.Placement.ListenPort,
		Provisioned: true, AuthorityRunning: true}
	secondCSR := secondServing
	secondCSR.AuthorityRunning, secondCSR.AuthorityCSRPEM = false, authorityCSR
	observeTieredCell(t, h, cell.ID, "archive-cap-csr", true, firstServing, secondCSR)
	observeTieredCell(t, h, cell.ID, "archive-cap-running", true, firstServing, secondServing)
	if ready, _ := h.manager.GetVolume(second.ID); ready.State != VolumeReady {
		t.Fatalf("second volume = %+v", ready)
	}

	archiving, err := h.manager.ArchiveVolume("archive-cap-first", ArchiveVolumeRequest{VolumeID: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	before := verifiedPlan(t, h.manager, cell.ID, *h.now).Generation
	if _, err := h.manager.ArchiveVolume("archive-cap-refused", ArchiveVolumeRequest{VolumeID: second.ID}); !errors.Is(err, ErrBusy) {
		t.Fatalf("archive at the per-cell cap = %v", err)
	}
	untouched, _ := h.manager.GetVolume(second.ID)
	if untouched.State != VolumeReady || untouched.ArchiveCycleStep != "" || untouched.ArchiveAttempt != "" {
		t.Fatalf("busy refusal changed volume state = %+v", untouched)
	}
	if after := verifiedPlan(t, h.manager, cell.ID, *h.now).Generation; after != before {
		t.Fatalf("busy refusal bumped the plan %d -> %d", before, after)
	}

	// At cursor "verifying" the exporter is proven absent and the outstanding
	// work is the Manager's own archive-store read, so the cell slot is free.
	quiesced := firstServing
	quiesced.AuthorityGeneration, quiesced.AuthorityRunning, quiesced.AuthorityAbsent, quiesced.QuiesceProven = archiving.AuthorityEpoch, false, true, true
	observeTieredCell(t, h, cell.ID, "archive-cap-quiesced", true, quiesced, secondServing)
	exporting, _ := h.manager.GetVolume(first.ID)
	seal := validArchiveSeal(exporting.ArchiveAttempt)
	sealed := quiesced
	sealed.QuiesceProven, sealed.ArchiveSealed = false, &seal
	observeTieredCell(t, h, cell.ID, "archive-cap-sealed", true, sealed, secondServing)
	if verifying, _ := h.manager.GetVolume(first.ID); verifying.ArchiveCycleStep != "verifying" {
		t.Fatalf("first cycle cursor = %+v", verifying)
	}
	if admitted, err := h.manager.ArchiveVolume("archive-cap-second", ArchiveVolumeRequest{VolumeID: second.ID}); err != nil || admitted.State != VolumeArchiving {
		t.Fatalf("archive after the cell slot freed = %+v, %v", admitted, err)
	}
}

func currentState(t *testing.T, h managerHarness) *State {
	t.Helper()
	var state State
	if err := h.store.View(func(current State) error { state = current; return nil }); err != nil {
		t.Fatal(err)
	}
	return &state
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
