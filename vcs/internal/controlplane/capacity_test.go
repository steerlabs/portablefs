package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAdmissionStatusPreservesStableRefusalClasses(t *testing.T) {
	for _, test := range []struct {
		err  error
		want AdmissionStatus
	}{
		{err: nil, want: "ADMISSIBLE"},
		{err: ErrCellUnavailable, want: "CELL_UNAVAILABLE"},
		{err: ErrCapacity, want: "CAPACITY_EXHAUSTED"},
		{err: ErrBusy, want: "BUSY"},
	} {
		if got := admissionStatus(test.err); got != test.want {
			t.Fatalf("admissionStatus(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

func TestAllocatorLifetimeExhaustionSurvivesVolumeDeletionAndIsCapacity(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("one-lifetime-placement", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct,
		FirstProjectID: 12_000, FirstServiceUID: 212_000, FirstPort: 32_000,
		LastProjectID: 12_000, LastServiceUID: 212_000, LastPort: 32_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	volume, err := h.manager.CreateVolume("lifetime-first", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, csr := testCSR(t)
	observeTieredVolume(t, h, cell.ID, "lifetime-csr", VolumeObservation{
		VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch,
		ProjectID: volume.Placement.ProjectID, ServiceUID: volume.Placement.ServiceUID,
		ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
		Provisioned: true, AuthorityCSRPEM: csr,
	})
	volume, _ = h.manager.GetVolume(volume.ID)
	observeTieredVolume(t, h, cell.ID, "lifetime-running", VolumeObservation{
		VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch,
		ProjectID: volume.Placement.ProjectID, ServiceUID: volume.Placement.ServiceUID,
		ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
		Provisioned: true, AuthorityRunning: true,
	})
	volume, _ = h.manager.GetVolume(volume.ID)
	destroying, err := h.manager.DestroyVolume("lifetime-delete", DestroyVolumeRequest{VolumeID: volume.ID, Reason: "deleted"})
	if err != nil {
		t.Fatal(err)
	}
	observeTieredVolume(t, h, cell.ID, "lifetime-quiesced", VolumeObservation{
		VolumeID: volume.ID, AuthorityGeneration: destroying.AuthorityEpoch,
		ProjectID: destroying.Placement.ProjectID, ServiceUID: destroying.Placement.ServiceUID,
		ServiceGID: destroying.Placement.ServiceGID, ListenPort: destroying.Placement.ListenPort,
		AuthorityAbsent: true, QuiesceProven: true,
	})
	destroying, _ = h.manager.GetVolume(volume.ID)
	observeTieredVolume(t, h, cell.ID, "lifetime-destroyed", VolumeObservation{
		VolumeID: volume.ID, AuthorityGeneration: destroying.AuthorityEpoch,
		ProjectID: destroying.Placement.ProjectID, ServiceUID: destroying.Placement.ServiceUID,
		ServiceGID: destroying.Placement.ServiceGID, ListenPort: destroying.Placement.ListenPort,
		AuthorityAbsent: true, DestroyProofSHA256: strings.Repeat("a", 64),
	})
	destroying, _ = h.manager.GetVolume(volume.ID)
	observeTieredVolume(t, h, cell.ID, "lifetime-released", VolumeObservation{
		VolumeID: volume.ID, AuthorityGeneration: destroying.AuthorityEpoch,
		ProjectID: destroying.Placement.ProjectID, ServiceUID: destroying.Placement.ServiceUID,
		ServiceGID: destroying.Placement.ServiceGID, ListenPort: destroying.Placement.ListenPort,
		AuthorityAbsent: true, Released: true,
	})
	if terminal, _ := h.manager.GetVolume(volume.ID); terminal.State != VolumeDestroyed || terminal.Placement != nil {
		t.Fatalf("terminal deletion = %+v", terminal)
	}
	if _, err := h.manager.CreateVolume("lifetime-second", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "other", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
	}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("allocation after deleted lifetime range = %v", err)
	}
	createResponse := serveControlRequest(t, testHTTPHandler(h.manager), "POST", "/v1/volumes", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "http-other", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
	}, RoleProduct, "opensteer", "lifetime-http-create")
	if createResponse.Code != 409 || !strings.Contains(createResponse.Body.String(), ErrCapacity.Error()) {
		t.Fatalf("allocator exhaustion HTTP classification status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}

	response := serveControlRequest(t, testHTTPHandler(h.manager), "GET", "/v1/capacity", nil, RoleProduct, "opensteer", "")
	if response.Code != 200 {
		t.Fatalf("capacity HTTP status=%d body=%s", response.Code, response.Body.String())
	}
	var report CapacityReport
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Pools[0].CreateAdmissible || report.Pools[0].CreateStatus != AdmissionCapacity {
		t.Fatalf("exhausted allocator capacity report = %+v", report.Pools[0])
	}
}

func TestPreBoundAdoptionPreservesExhaustedCursorAndReportsCapacity(t *testing.T) {
	h := newManagerHarness(t)
	declaration := RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct,
		FirstProjectID: 12_000, FirstServiceUID: 212_000, FirstPort: 32_000,
		LastProjectID: 12_000, LastServiceUID: 212_000, LastPort: 32_000,
	}
	cell, err := h.manager.RegisterCell("exhausted-pre-bound-cell", declaration)
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	if _, err := h.manager.CreateVolume("exhausted-pre-bound-first", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.TransactNatural("test-exhausted-pre-bound-registration", h.now.Unix(), func(state *State) (any, bool, error) {
		current := state.Cells[cell.ID]
		current.RegistrationSHA256 = strings.Repeat("b", 64)
		current.LastProjectID = 0
		current.LastServiceUID = 0
		current.LastPort = 0
		state.Cells[cell.ID] = current
		return current, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	before := currentState(t, h).Cells[cell.ID]
	if before.NextProjectID != declaration.LastProjectID+1 ||
		before.NextServiceUID != declaration.LastServiceUID+1 ||
		before.NextPort != declaration.LastPort+1 {
		t.Fatalf("fixture allocator cursors are not exhausted: %+v", before)
	}
	sequence := h.store.sequence
	pinned, err := h.manager.ConvergeCell(cell.ID, declaration)
	if err != nil {
		t.Fatalf("fully exhausted pre-bound adoption = %v", err)
	}
	want := before
	want.LastProjectID = declaration.LastProjectID
	want.LastServiceUID = declaration.LastServiceUID
	want.LastPort = declaration.LastPort
	want.RegistrationSHA256 = pinned.RegistrationSHA256
	if !reflect.DeepEqual(pinned, want) || h.store.sequence != sequence+1 {
		t.Fatalf("exhausted adoption changed live state or append count: got=%+v want=%+v sequence=%d->%d", pinned, want, sequence, h.store.sequence)
	}
	if _, err := h.manager.CreateVolume("exhausted-pre-bound-second", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "other", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
	}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("allocation after exhausted pre-bound adoption = %v", err)
	}

	response := serveControlRequest(t, testHTTPHandler(h.manager), "GET", "/v1/capacity", nil, RoleProduct, "opensteer", "")
	if response.Code != 200 {
		t.Fatalf("capacity HTTP status=%d body=%s", response.Code, response.Body.String())
	}
	var report CapacityReport
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	for _, pool := range report.Pools {
		if pool.Pool == PoolProduct {
			if pool.CreateAdmissible || pool.CreateStatus != AdmissionCapacity {
				t.Fatalf("exhausted adopted allocator capacity report = %+v", pool)
			}
			return
		}
	}
	t.Fatalf("product pool missing from capacity report: %+v", report)
}

func TestPlacementAdmissionUsesPendingChargesAndStaleUsageFailsClosed(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.ProvisionFloorBytes = 700 << 20
	h.manager.cfg.ProvisionFloorInodes = 1000
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("capacity-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 1500 << 20, CapacityInodes: 100_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort})
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

func TestConcurrentCreatesSerializeAllocatorReservationsAndSurviveReopen(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("concurrent-cell", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 100 << 30,
		CapacityInodes: 10_000_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	cell = prepareCellForAdmission(t, h, cell)
	const creates = 32
	type result struct {
		volume VolumeView
		err    error
	}
	results := make(chan result, creates)
	var group sync.WaitGroup
	for index := range creates {
		group.Add(1)
		go func() {
			defer group.Done()
			volume, createErr := h.manager.CreateVolume(fmt.Sprintf("concurrent-create-%02d", index), CreateVolumeRequest{
				AuthorizationDomain: "org", Owner: fmt.Sprintf("owner-%02d", index), ProductIssuer: "opensteer",
				QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
			})
			results <- result{volume: volume, err: createErr}
		}()
	}
	group.Wait()
	close(results)

	volumeIDs := make(map[string]struct{}, creates)
	allocatorTuples := make(map[string]struct{}, creates)
	projectIDs := make(map[uint32]struct{}, creates)
	serviceUIDs := make(map[uint32]struct{}, creates)
	ports := make(map[uint16]struct{}, creates)
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent create = %v", result.err)
		}
		if result.volume.Placement == nil {
			t.Fatalf("concurrent create had no placement = %+v", result.volume)
		}
		volumeIDs[result.volume.ID] = struct{}{}
		tuple := fmt.Sprintf("%d/%d/%d", result.volume.Placement.ProjectID, result.volume.Placement.ServiceUID, result.volume.Placement.ListenPort)
		allocatorTuples[tuple] = struct{}{}
		projectIDs[result.volume.Placement.ProjectID] = struct{}{}
		serviceUIDs[result.volume.Placement.ServiceUID] = struct{}{}
		ports[result.volume.Placement.ListenPort] = struct{}{}
	}
	if len(volumeIDs) != creates || len(allocatorTuples) != creates || len(projectIDs) != creates || len(serviceUIDs) != creates || len(ports) != creates {
		t.Fatalf("unique volumes/tuples/projects/uids/ports = %d/%d/%d/%d/%d, want %d each",
			len(volumeIDs), len(allocatorTuples), len(projectIDs), len(serviceUIDs), len(ports), creates)
	}
	state := currentState(t, h)
	gotCell := state.Cells[cell.ID]
	if len(state.Volumes) != creates || gotCell.PlanGeneration != cell.PlanGeneration+creates ||
		gotCell.NextProjectID != cell.NextProjectID+creates || gotCell.NextServiceUID != cell.NextServiceUID+creates ||
		gotCell.NextPort != cell.NextPort+creates {
		t.Fatalf("serialized durable allocation = cell %+v, volumes %d", gotCell, len(state.Volumes))
	}
	for _, volume := range state.Volumes {
		if volume.Placement == nil || volume.Placement.PendingBytes != h.manager.cfg.ProvisionFloorBytes ||
			volume.Placement.PendingInodes != h.manager.cfg.ProvisionFloorInodes {
			t.Fatalf("missing durable reservation = %+v", volume)
		}
	}

	statePath := h.store.path
	managerConfig := h.manager.cfg
	if err := h.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	managerConfig.Store = reopened
	restarted, err := NewManager(managerConfig)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := restarted.ListVolumes()
	if err != nil || len(listed.Volumes) != creates {
		t.Fatalf("reopened volumes = %d, %v", len(listed.Volumes), err)
	}
	if err := reopened.View(func(current State) error {
		currentCell := current.Cells[cell.ID]
		if currentCell.NextProjectID != cell.NextProjectID+creates || currentCell.NextServiceUID != cell.NextServiceUID+creates ||
			currentCell.NextPort != cell.NextPort+creates || currentCell.PlanGeneration != cell.PlanGeneration+creates {
			t.Fatalf("reopened allocator/plan state = %+v", currentCell)
		}
		for id, volume := range current.Volumes {
			if _, ok := volumeIDs[id]; !ok || volume.Placement == nil {
				t.Fatalf("reopened volume identity = %s %+v", id, volume)
			}
			tuple := fmt.Sprintf("%d/%d/%d", volume.Placement.ProjectID, volume.Placement.ServiceUID, volume.Placement.ListenPort)
			if _, ok := allocatorTuples[tuple]; !ok {
				t.Fatalf("reopened allocator tuple = %s", tuple)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFailedReconciliationAgesAvailabilityWithoutReleasingReservations(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("failed-reconcile-cell", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 10 << 30,
		CapacityInodes: 1_000_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	prepareCellForAdmission(t, h, cell)
	volume, err := h.manager.CreateVolume("unreconciled-volume", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	before := currentState(t, h)
	beforeSequence := h.store.sequence
	*h.now = h.now.Add(max(h.manager.cfg.ObservedStaleAfter, h.manager.cfg.UsageStaleAfter) + time.Second)
	if _, err := h.manager.CreateVolume("cell-unavailable-create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner-2", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
	}); !errors.Is(err, ErrCellUnavailable) {
		t.Fatalf("aged failed reconciliation = %v", err)
	}
	after := currentState(t, h)
	if h.store.sequence != beforeSequence || len(after.Volumes) != len(before.Volumes) ||
		after.Cells[cell.ID].NextProjectID != before.Cells[cell.ID].NextProjectID {
		t.Fatalf("unavailable refusal mutated durable state: before=%+v after=%+v", before.Cells[cell.ID], after.Cells[cell.ID])
	}
	retained := after.Volumes[volume.ID]
	if retained.Placement == nil || retained.Placement.PendingBytes != h.manager.cfg.ProvisionFloorBytes ||
		retained.Placement.PendingInodes != h.manager.cfg.ProvisionFloorInodes {
		t.Fatalf("failed reconciliation released its charge = %+v", retained)
	}
	report, err := h.manager.Capacity()
	if err != nil || report.Pools[0].CreateAdmissible || report.Pools[0].CreateStatus != AdmissionCellUnavailable {
		t.Fatalf("unavailable capacity report = %+v, %v", report, err)
	}
}

func TestFreshHeartbeatCannotSubstituteForStaleFullUsage(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("stale-full-usage-cell", RegisterCellRequest{
		ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 10 << 30,
		CapacityInodes: 1_000_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	cell = prepareCellForAdmission(t, h, cell)
	*h.now = h.now.Add(h.manager.cfg.UsageStaleAfter + time.Second)
	if err := h.manager.HeartbeatCell(CellHeartbeat{
		CellID: cell.ID, PlanGeneration: cell.PlanGeneration, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.CreateVolume("stale-full-usage-create", CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: PoolProduct,
	}); !errors.Is(err, ErrCellUnavailable) {
		t.Fatalf("fresh heartbeat with stale full usage = %v", err)
	}
	report, err := h.manager.Capacity()
	if err != nil || report.Pools[0].CreateStatus != AdmissionCellUnavailable {
		t.Fatalf("stale full-usage report = %+v, %v", report, err)
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
		CapacityBytes: 3 << 30, CapacityInodes: 100_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort})
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
		CapacityBytes: 40 << 30, CapacityInodes: 2_000_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort})
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
	if err != nil || !report.Pools[0].CreateAdmissible || report.Pools[0].CreateStatus != AdmissionAdmissible {
		t.Fatalf("capacity after periodic unchanged observations = %+v, %v", report, err)
	}
	for _, volume := range currentState(t, h).Volumes {
		if h.now.Unix()-volume.Placement.UsedObservedUnix > int64(h.manager.cfg.UsageStaleAfter/time.Second) {
			t.Fatalf("periodic observation left stale usage = %+v", volume.Placement)
		}
	}
}

func TestPlacementAdmissionDoesNotConfuseDesiredPlanConvergenceWithCapacity(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1
	cell, err := h.manager.RegisterCell("convergence-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111",
		AvailabilityZone: "zone-a", AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 40 << 30, CapacityInodes: 2_000_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort})
	if err != nil {
		t.Fatal(err)
	}
	cell = prepareCellForAdmission(t, h, cell)
	appliedGeneration := cell.PlanGeneration
	var observations []VolumeObservation
	for index := range 10 {
		volume, createErr := h.manager.CreateVolume(fmt.Sprintf("convergence-volume-%d", index), CreateVolumeRequest{
			AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
			QuotaBytes: 10 << 30, QuotaInodes: 1_000_000, Pool: PoolProduct,
		})
		if createErr != nil {
			t.Fatalf("create %d while the complete desired plan was converging = %v", index, createErr)
		}
		observations = append(observations, VolumeObservation{
			VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
		})
	}
	state := currentState(t, h)
	desired := state.Cells[cell.ID]
	if desired.PlanGeneration != appliedGeneration+10 || !h.manager.cellLive(desired, h.now.Unix()) || h.manager.cellConverged(desired, h.now.Unix()) {
		t.Fatalf("desired/applied generations did not remain distinct: desired=%d applied=%d live=%v converged=%v",
			desired.PlanGeneration, appliedGeneration, h.manager.cellLive(desired, h.now.Unix()), h.manager.cellConverged(desired, h.now.Unix()))
	}
	report, err := h.manager.Capacity()
	if err != nil || !report.Pools[0].CreateAdmissible || report.Pools[0].PendingBytes != 10*h.manager.cfg.ProvisionFloorBytes {
		t.Fatalf("capacity during convergence = %+v, %v", report, err)
	}

	// A heartbeat racing the desired-plan mutations still proves the cell
	// processes are live. It does not claim that the newer complete plan has
	// been applied.
	*h.now = h.now.Add(time.Second)
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: cell.ID, PlanGeneration: appliedGeneration,
		ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix()}); err != nil {
		t.Fatalf("live heartbeat from the last applied generation = %v", err)
	}
	if !h.manager.cellLive(desired, h.now.Unix()) || h.manager.cellConverged(desired, h.now.Unix()) {
		t.Fatalf("racing heartbeat changed convergence: live=%v converged=%v",
			h.manager.cellLive(desired, h.now.Unix()), h.manager.cellConverged(desired, h.now.Unix()))
	}
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: cell.ID, PlanGeneration: desired.PlanGeneration + 1,
		ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix()}); !errors.Is(err, ErrConflict) {
		t.Fatalf("never-issued generation heartbeat = %v", err)
	}

	observeTieredCell(t, h, cell.ID, "convergence-applied", true, observations...)
	desired = currentState(t, h).Cells[cell.ID]
	if !h.manager.cellConverged(desired, h.now.Unix()) {
		t.Fatal("the exact applied complete plan did not restore convergence")
	}
	// A genuinely delayed lower-generation packet has an older cell timestamp
	// and cannot replace the newer convergence evidence.
	delayedObservedUnix := h.now.Add(-time.Second).Unix()
	*h.now = h.now.Add(time.Second)
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: cell.ID, PlanGeneration: appliedGeneration,
		ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: delayedObservedUnix}); err != nil {
		t.Fatalf("delayed older heartbeat = %v", err)
	}
	if !h.manager.cellConverged(desired, h.now.Unix()) {
		t.Fatal("a delayed older heartbeat replaced newer convergence evidence")
	}
	// A newer report at the lower generation is not delayed: it says the cell
	// regressed and must immediately close the convergence gate.
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: cell.ID, PlanGeneration: appliedGeneration,
		ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix()}); err != nil {
		t.Fatalf("newer regressed heartbeat = %v", err)
	}
	if !h.manager.cellLive(desired, h.now.Unix()) || h.manager.cellConverged(desired, h.now.Unix()) {
		t.Fatalf("newer regression did not fail closed: live=%v converged=%v",
			h.manager.cellLive(desired, h.now.Unix()), h.manager.cellConverged(desired, h.now.Unix()))
	}
	// Conflicting generations with the same second are ambiguous. Retaining
	// the lower generation is conservative until a later observation arrives.
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: cell.ID, PlanGeneration: desired.PlanGeneration,
		ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix()}); err != nil {
		t.Fatalf("same-time exact heartbeat = %v", err)
	}
	if h.manager.cellConverged(desired, h.now.Unix()) {
		t.Fatal("same-time conflicting heartbeat reopened convergence")
	}
	*h.now = h.now.Add(time.Second)
	if err := h.manager.HeartbeatCell(CellHeartbeat{CellID: cell.ID, PlanGeneration: desired.PlanGeneration,
		ManagerReleaseID: h.manager.ReleaseIdentity(), AgentReleaseID: "agent-test", HelperReleaseID: "helper-test", ObservedUnix: h.now.Unix()}); err != nil {
		t.Fatalf("later exact heartbeat = %v", err)
	}
	if !h.manager.cellConverged(desired, h.now.Unix()) {
		t.Fatal("a later exact heartbeat did not restore convergence")
	}
}

// Restore work requires a cell whose helper can hydrate; creates never do.
func TestRestoreAdmissionRequiresAnArchiveCapableCell(t *testing.T) {
	h := newManagerHarness(t)
	cell, err := h.manager.RegisterCell("restore-capability-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111",
		AvailabilityZone: "zone-a", AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort})
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
	if err != nil || report.Pools[0].Pool != PoolProduct || !report.Pools[0].CreateAdmissible || report.Pools[0].RestoreAdmissible ||
		report.Pools[0].CreateStatus != AdmissionAdmissible || report.Pools[0].RestoreStatus != AdmissionCapacity {
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
		CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort})
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
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 4 << 30, CapacityInodes: 100_000, Pool: PoolSystem,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort})
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
	if len(report.Pools) != 3 || report.Pools[1].Pool != PoolSystem || report.Pools[1].CapacityBytes != 5<<30 || report.Pools[1].CreateAdmissible ||
		report.Pools[1].CreateStatus != AdmissionCapacity {
		t.Fatalf("capacity report = %+v", report)
	}
}

func TestRestorePriorityUsesWakeBurstHeadroom(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.WakeBurstBytes = 1500 << 20
	cell, err := h.manager.RegisterCell("priority-cell", RegisterCellRequest{ID: "11111111-1111-4111-8111-111111111111", AvailabilityZone: "zone-a",
		AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test", CapacityBytes: 2 << 30, CapacityInodes: 100_000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort})
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
		AuthorityDNSZone: "new.test", CapacityBytes: 1 << 30, CapacityInodes: 1000, Pool: PoolProduct,
		LastProjectID: testLastProjectID, LastServiceUID: testLastServiceUID, LastPort: testLastPort}); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("abandoned re-register = %v", err)
	}
	if _, err := h.manager.CreateVolume("abandoned-admission", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 1000, Pool: PoolProduct}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("abandoned cell admission = %v", err)
	}
}
