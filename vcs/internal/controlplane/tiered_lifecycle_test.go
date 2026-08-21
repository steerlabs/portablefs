package controlplane

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

type fakeArchiveVerifier struct {
	err   error
	calls int
}

func (verifier *fakeArchiveVerifier) Verify(ArchiveRecord) error {
	verifier.calls++
	return verifier.err
}

type fakeArchivePurger struct {
	err   error
	calls int
}

func (purger *fakeArchivePurger) Purge(ArchiveRecord) error { purger.calls++; return purger.err }

func TestArchiveReleaseAndCrossCellWakeLifecycle(t *testing.T) {
	h := newManagerHarness(t)
	verifier := &fakeArchiveVerifier{}
	h.manager.cfg.ArchiveVerifier = verifier
	first, volume := readyVolumeForMount(t, h)
	second, err := h.manager.RegisterCell("second-cell", RegisterCellRequest{ID: "33333333-3333-4333-8333-333333333333", AvailabilityZone: "zone-b",
		AuthorityHost: "cell-b.test", AuthorityDNSZone: "cell-b.test", CapacityBytes: 10 << 30, CapacityInodes: 1_000_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	second = prepareCellForAdmission(t, h, second)

	archiving, err := h.manager.ArchiveVolume("archive", ArchiveVolumeRequest{VolumeID: volume.ID})
	if err != nil || archiving.State != VolumeArchiving || archiving.ArchiveCycleStep != "quiescing" || !cellplan.ValidID(archiving.ArchiveAttempt) {
		t.Fatalf("ArchiveVolume = %+v, %v", archiving, err)
	}
	plan := verifiedPlan(t, h.manager, first.ID, *h.now)
	if plan.Version != 2 || plan.Volumes[0].Phase != cellplan.PhaseArchive || plan.Volumes[0].ArchiveTo == nil {
		t.Fatalf("archive plan = %+v", plan)
	}
	observeTieredVolume(t, h, first.ID, "quiesced", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: archiving.AuthorityEpoch,
		ProjectID: archiving.Placement.ProjectID, ServiceUID: archiving.Placement.ServiceUID, ServiceGID: archiving.Placement.ServiceGID,
		ListenPort: archiving.Placement.ListenPort, Provisioned: true, AuthorityAbsent: true, QuiesceProven: true})
	exporting, _ := h.manager.GetVolume(volume.ID)
	if exporting.ArchiveCycleStep != "exporting" || exporting.AuthorityEpoch != volume.AuthorityEpoch {
		t.Fatalf("exporting = %+v", exporting)
	}

	sealed := validArchiveSeal(exporting.ArchiveAttempt)
	observeTieredVolume(t, h, first.ID, "sealed", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: exporting.AuthorityEpoch,
		ProjectID: exporting.Placement.ProjectID, ServiceUID: exporting.Placement.ServiceUID, ServiceGID: exporting.Placement.ServiceGID,
		ListenPort: exporting.Placement.ListenPort, Provisioned: true, AuthorityAbsent: true, ArchiveSealed: &sealed})
	// The seal is durably recorded at "verifying"; verification runs as its
	// own unlocked pass, never inside the observation transaction.
	verifying, _ := h.manager.GetVolume(volume.ID)
	if verifier.calls != 0 || verifying.State != VolumeArchiving || verifying.ArchiveCycleStep != "verifying" || !storeHasPendingSeal(t, h, volume.ID) {
		t.Fatalf("verifying = %+v, verifier calls=%d", verifying, verifier.calls)
	}
	if err := h.manager.NoteVerify(volume.ID); err != nil {
		t.Fatalf("NoteVerify = %v", err)
	}
	archived, _ := h.manager.GetVolume(volume.ID)
	if verifier.calls != 1 || archived.State != VolumeArchived || archived.ArchiveCycleStep != "sealed" || archived.ArchiveSummary == nil || storeHasPendingSeal(t, h, volume.ID) {
		t.Fatalf("archived = %+v, verifier calls=%d", archived, verifier.calls)
	}
	accelerated, err := h.manager.WakeVolume("wake-sealed", WakeVolumeRequest{VolumeID: volume.ID})
	if err != nil || !accelerated.WakeRequested || accelerated.Placement == nil || accelerated.State != VolumeArchived {
		t.Fatalf("wake during sealed = %+v, %v", accelerated, err)
	}
	plan = verifiedPlan(t, h.manager, first.ID, *h.now)
	if plan.Volumes[0].Phase != cellplan.PhaseDestroy {
		t.Fatalf("destroy plan = %+v", plan.Volumes[0])
	}
	proof := strings.Repeat("d", 64)
	observeTieredVolume(t, h, first.ID, "destroyed", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: archived.AuthorityEpoch,
		ProjectID: archived.Placement.ProjectID, ServiceUID: archived.Placement.ServiceUID, ServiceGID: archived.Placement.ServiceGID,
		ListenPort: archived.Placement.ListenPort, AuthorityAbsent: true, DestroyProofSHA256: proof})
	destroyed, _ := h.manager.GetVolume(volume.ID)
	if destroyed.ArchiveCycleStep != "destroyed" || destroyed.Placement.DestroyProofSHA256 != proof {
		t.Fatalf("destroyed placement = %+v", destroyed)
	}
	stillSingle, err := h.manager.WakeVolume("wake-destroyed", WakeVolumeRequest{VolumeID: volume.ID})
	if err != nil || !stillSingle.WakeRequested || stillSingle.Placement == nil ||
		stillSingle.Placement.CellID != first.ID || stillSingle.PlacementSequence != 1 {
		t.Fatalf("wake during destroyed = %+v, %v", stillSingle, err)
	}
	plan = verifiedPlan(t, h.manager, first.ID, *h.now)
	if plan.Volumes[0].Phase != cellplan.PhaseRelease || plan.Volumes[0].ReleaseProof == nil || plan.Volumes[0].ReleaseProof.DestroyProofSHA256 != proof {
		t.Fatalf("release plan = %+v", plan.Volumes[0])
	}
	observeTieredVolume(t, h, first.ID, "released", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: destroyed.AuthorityEpoch,
		ProjectID: destroyed.Placement.ProjectID, ServiceUID: destroyed.Placement.ServiceUID, ServiceGID: destroyed.Placement.ServiceGID,
		ListenPort: destroyed.Placement.ListenPort, AuthorityAbsent: true, Released: true})
	released, _ := h.manager.GetVolume(volume.ID)
	if released.Placement != nil || released.ArchiveCycleStep != "released" {
		t.Fatalf("released = %+v", released)
	}
	if plan := verifiedPlan(t, h.manager, first.ID, *h.now); len(plan.Volumes) != 0 {
		t.Fatalf("released plan = %+v", plan)
	}
	observeTieredVolume(t, h, first.ID, "stale-release-replay", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: released.AuthorityEpoch, Released: true})
	if _, err := h.manager.DecommissionCell("decommission-source", first.ID, DecommissionCellRequest{Reason: "archive drain"}); err != nil {
		t.Fatal(err)
	}

	woken, err := h.manager.WakeVolume("wake", WakeVolumeRequest{VolumeID: volume.ID})
	if err != nil || woken.State != VolumeRestoring || woken.Placement == nil || woken.Placement.CellID != second.ID ||
		woken.PlacementSequence != 2 || woken.AuthorityEpoch != volume.AuthorityEpoch+1 || !strings.Contains(woken.Placement.AuthorityServerName, "-p2.") {
		t.Fatalf("WakeVolume = %+v, %v", woken, err)
	}
	plan = verifiedPlan(t, h.manager, second.ID, *h.now)
	if plan.Volumes[0].Phase != cellplan.PhaseRestore || plan.Volumes[0].RestoreFrom == nil || plan.Volumes[0].RestoreFrom.Attempt != sealed.Attempt {
		t.Fatalf("restore plan = %+v", plan.Volumes[0])
	}
	_, authorityCSR := testCSR(t)
	observeTieredVolume(t, h, second.ID, "namespace-ready", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: woken.AuthorityEpoch,
		ProjectID: woken.Placement.ProjectID, ServiceUID: woken.Placement.ServiceUID, ServiceGID: woken.Placement.ServiceGID,
		ListenPort: woken.Placement.ListenPort, Provisioned: true, AuthorityRunning: true, AuthorityCSRPEM: authorityCSR, RestoreNamespaceReady: true})
	restoring, _ := h.manager.GetVolume(volume.ID)
	observeTieredVolume(t, h, second.ID, "restore-serving", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: woken.AuthorityEpoch,
		ProjectID: woken.Placement.ProjectID, ServiceUID: woken.Placement.ServiceUID, ServiceGID: woken.Placement.ServiceGID,
		ListenPort: woken.Placement.ListenPort, Provisioned: true, AuthorityRunning: true, AuthorityCSRPEM: authorityCSR, RestoreNamespaceReady: true})
	clientPublic, clientCSR := testCSR(t)
	spki, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(spki)
	authorization, err := h.manager.IssueMount("restore-enrollment", IssueMountRequest{VolumeID: volume.ID,
		ProductAuthorization: signedProductAuthorization(t, h, restoring.Volume, peer, "restore-enrollment", []string{"read"}),
		ClientCSRPEM:         clientCSR, Access: []string{"read"}, AutomaticReauthorization: true})
	if err != nil || authorization.EnrollmentID == "" {
		t.Fatalf("restore enrollment = %+v, %v", authorization, err)
	}
	observeTieredVolume(t, h, second.ID, "restore-converged", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: woken.AuthorityEpoch,
		ProjectID: woken.Placement.ProjectID, ServiceUID: woken.Placement.ServiceUID, ServiceGID: woken.Placement.ServiceGID,
		ListenPort: woken.Placement.ListenPort, Provisioned: true, AuthorityRunning: true, RestoreNamespaceReady: true, RestoreConverged: true})
	converged, _ := h.manager.GetVolume(volume.ID)
	if converged.State != VolumeReady || converged.RestoreStep != "" || converged.Placement.PendingBytes == 0 {
		t.Fatalf("restore convergence = %+v", converged)
	}
	if plan := verifiedPlan(t, h.manager, second.ID, *h.now); plan.Volumes[0].Phase != cellplan.PhaseServe || plan.Volumes[0].RestoreFrom != nil {
		t.Fatalf("post-restore plan = %+v", plan.Volumes[0])
	}
	*h.now = h.now.Add(time.Second)
	observeTieredVolume(t, h, second.ID, "post-convergence-usage", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: woken.AuthorityEpoch,
		ProjectID: woken.Placement.ProjectID, ServiceUID: woken.Placement.ServiceUID, ServiceGID: woken.Placement.ServiceGID,
		ListenPort: woken.Placement.ListenPort, Provisioned: true, AuthorityRunning: true, UsedBytes: sealed.SealedAllocatedBytes, UsedInodes: sealed.SealedInodes})
	measured, _ := h.manager.GetVolume(volume.ID)
	if measured.Placement.PendingBytes != 0 || measured.Placement.PendingInodes != 0 || measured.RestoreConvergedUnix != 0 {
		t.Fatalf("restore pending charge was not cleared after convergence: %+v", measured.Placement)
	}
	rearchiving, err := h.manager.ArchiveVolume("rearchive", ArchiveVolumeRequest{VolumeID: volume.ID})
	if err != nil || rearchiving.ArchiveSummary == nil || rearchiving.State != VolumeArchiving {
		t.Fatalf("rearchive with retained checkpoint = %+v, %v", rearchiving, err)
	}
	readyAgain, err := h.manager.WakeVolume("cancel-rearchive", WakeVolumeRequest{VolumeID: volume.ID})
	if err != nil || readyAgain.State != VolumeReady || readyAgain.ArchiveSummary == nil {
		t.Fatalf("cancel rearchive = %+v, %v", readyAgain, err)
	}
	if _, err := h.manager.DestroyVolume("delete-retained", DestroyVolumeRequest{VolumeID: volume.ID, Reason: "workspace deleted"}); !errors.Is(err, ErrArchiveUnsupported) {
		t.Fatalf("delete retained checkpoint without purger = %v", err)
	}
	purger := &fakeArchivePurger{}
	h.manager.cfg.ArchivePurger = purger
	deleting, err := h.manager.DestroyVolume("delete-retained", DestroyVolumeRequest{VolumeID: volume.ID, Reason: "workspace deleted"})
	if err != nil || deleting.State != VolumeDestroying || deleting.ArchiveSummary != nil || purger.calls != 1 {
		t.Fatalf("delete retained checkpoint = %+v, calls=%d, err=%v", deleting, purger.calls, err)
	}
}

func TestWakeCancelsPreSealAndVerificationRetriesRemainNonDestructive(t *testing.T) {
	h := newManagerHarness(t)
	verifier := &fakeArchiveVerifier{err: errors.New("archive store down")}
	h.manager.cfg.ArchiveVerifier = verifier
	cell, volume := readyVolumeForMount(t, h)
	archiving, err := h.manager.ArchiveVolume("archive-cancel", ArchiveVolumeRequest{VolumeID: volume.ID})
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientCSR := testCSR(t)
	spki, err := x509.MarshalPKIXPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer := sha256.Sum256(spki)
	if _, err := h.manager.IssueMount("archive-mount-refused", IssueMountRequest{VolumeID: volume.ID,
		ProductAuthorization: signedProductAuthorization(t, h, archiving.Volume, peer, "archive-mount-refused", []string{"read"}),
		ClientCSRPEM:         clientCSR, Access: []string{"read"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("archive mount = %v", err)
	}
	observeTieredVolume(t, h, cell.ID, "archive-absent-without-proof", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: archiving.AuthorityEpoch,
		ProjectID: archiving.Placement.ProjectID, ServiceUID: archiving.Placement.ServiceUID, ServiceGID: archiving.Placement.ServiceGID,
		ListenPort: archiving.Placement.ListenPort, AuthorityAbsent: true})
	if still, _ := h.manager.GetVolume(volume.ID); still.State != VolumeArchiving || still.ArchiveCycleStep != "quiescing" {
		t.Fatalf("archive auto-fenced = %+v", still)
	}
	cancelled, err := h.manager.WakeVolume("wake-cancel", WakeVolumeRequest{VolumeID: volume.ID})
	if err != nil || cancelled.State != VolumeReady || cancelled.ArchiveAttempt != "" || cancelled.AuthorityEpoch != archiving.AuthorityEpoch {
		t.Fatalf("cancelled = %+v, %v", cancelled, err)
	}

	archiving, _ = h.manager.ArchiveVolume("archive-retry", ArchiveVolumeRequest{VolumeID: volume.ID})
	observeTieredVolume(t, h, cell.ID, "retry-quiesced", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: archiving.AuthorityEpoch,
		ProjectID: archiving.Placement.ProjectID, ServiceUID: archiving.Placement.ServiceUID, ServiceGID: archiving.Placement.ServiceGID,
		ListenPort: archiving.Placement.ListenPort, Provisioned: true, AuthorityAbsent: true, QuiesceProven: true})
	exporting, _ := h.manager.GetVolume(volume.ID)
	seal := validArchiveSeal(exporting.ArchiveAttempt)
	observeTieredVolume(t, h, cell.ID, "retry-sealed", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: exporting.AuthorityEpoch,
		ProjectID: exporting.Placement.ProjectID, ServiceUID: exporting.Placement.ServiceUID, ServiceGID: exporting.Placement.ServiceGID,
		ListenPort: exporting.Placement.ListenPort, Provisioned: true, AuthorityAbsent: true, ArchiveSealed: &seal})
	verifying, _ := h.manager.GetVolume(volume.ID)
	if verifying.State != VolumeArchiving || verifying.ArchiveCycleStep != "verifying" || !storeHasPendingSeal(t, h, volume.ID) || verifying.ArchiveSummary != nil {
		t.Fatalf("verifying = %+v", verifying)
	}
	if err := h.manager.NoteVerify(volume.ID); !errors.Is(err, ErrArchiveStoreUnavailable) {
		t.Fatalf("NoteVerify outage = %v", err)
	}
	verifier.err = nil
	committed, err := h.manager.RetryVerification("retry-verify", volume.ID)
	if err != nil || committed.State != VolumeArchived {
		t.Fatalf("RetryVerification = %+v, %v", committed, err)
	}
}

func TestDestroyLiveVolumeRunsFenceDestroyRelease(t *testing.T) {
	h := newManagerHarness(t)
	cell, volume := readyVolumeForMount(t, h)
	destroying, err := h.manager.DestroyVolume("delete", DestroyVolumeRequest{VolumeID: volume.ID, Reason: "workspace deleted"})
	if err != nil || destroying.State != VolumeDestroying || destroying.ArchiveCycleStep != "quiescing" {
		t.Fatalf("DestroyVolume = %+v, %v", destroying, err)
	}
	if plan := verifiedPlan(t, h.manager, cell.ID, *h.now); plan.Volumes[0].Phase != cellplan.PhaseFence {
		t.Fatalf("destroy quiesce plan = %+v", plan.Volumes[0])
	}
	observeTieredVolume(t, h, cell.ID, "delete-quiesced", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: destroying.AuthorityEpoch,
		ProjectID: destroying.Placement.ProjectID, ServiceUID: destroying.Placement.ServiceUID, ServiceGID: destroying.Placement.ServiceGID,
		ListenPort: destroying.Placement.ListenPort, AuthorityAbsent: true, QuiesceProven: true})
	destroying, _ = h.manager.GetVolume(volume.ID)
	if destroying.ArchiveCycleStep != "destroying" {
		t.Fatalf("destroy ready = %+v", destroying)
	}
	if plan := verifiedPlan(t, h.manager, cell.ID, *h.now); plan.Volumes[0].Phase != cellplan.PhaseDestroy {
		t.Fatalf("destroy plan = %+v", plan.Volumes[0])
	}
	proof := strings.Repeat("e", 64)
	observeTieredVolume(t, h, cell.ID, "delete-proof", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: destroying.AuthorityEpoch,
		ProjectID: destroying.Placement.ProjectID, ServiceUID: destroying.Placement.ServiceUID, ServiceGID: destroying.Placement.ServiceGID,
		ListenPort: destroying.Placement.ListenPort, AuthorityAbsent: true, DestroyProofSHA256: proof})
	destroying, _ = h.manager.GetVolume(volume.ID)
	observeTieredVolume(t, h, cell.ID, "delete-release", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: destroying.AuthorityEpoch,
		ProjectID: destroying.Placement.ProjectID, ServiceUID: destroying.Placement.ServiceUID, ServiceGID: destroying.Placement.ServiceGID,
		ListenPort: destroying.Placement.ListenPort, AuthorityAbsent: true, Released: true})
	terminal, _ := h.manager.GetVolume(volume.ID)
	if terminal.State != VolumeDestroyed || terminal.Placement != nil || terminal.ArchiveSummary != nil || terminal.DestroyedUnix == 0 {
		t.Fatalf("terminal delete = %+v", terminal)
	}
	if err := h.store.View(func(state State) error {
		if _, retained := state.Receipts["delete"]; retained {
			t.Fatal("terminal deletion retained its pre-terminal volume receipt")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDestroyArchivedRequiresPurgerAndCommitsTerminalAfterPurge(t *testing.T) {
	h := newManagerHarness(t)
	_, volume := readyVolumeForMount(t, h)
	seal := validArchiveSeal("33333333-3333-4333-8333-333333333333")
	record, err := archiveRecordFromObservation(Volume{ArchiveAttempt: seal.Attempt, AuthorityEpoch: volume.AuthorityEpoch}, &seal, h.now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.TransactNatural("seed-released-archive", h.now.Unix(), func(state *State) (any, bool, error) {
		v := state.Volumes[volume.ID]
		v.State = VolumeArchived
		v.Placement = nil
		v.Archive = &record
		v.ArchiveCycleStep = "released"
		v.UpdatedUnix = h.now.Unix()
		state.Volumes[v.ID] = v
		return state.volumeView(v), true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.DestroyVolume("purge-unavailable", DestroyVolumeRequest{VolumeID: volume.ID, Reason: "delete"}); !errors.Is(err, ErrArchiveUnsupported) {
		t.Fatalf("missing purger = %v", err)
	}
	if current, _ := h.manager.GetVolume(volume.ID); current.State != VolumeArchived {
		t.Fatalf("unavailable purge changed state = %+v", current)
	}
	purger := &fakeArchivePurger{}
	h.manager.cfg.ArchivePurger = purger
	terminal, err := h.manager.DestroyVolume("purge", DestroyVolumeRequest{VolumeID: volume.ID, Reason: "delete"})
	if err != nil || purger.calls != 1 || terminal.State != VolumeDestroyed || terminal.ArchiveSummary != nil || terminal.DestroyedUnix == 0 {
		t.Fatalf("archive purge = %+v calls=%d err=%v", terminal, purger.calls, err)
	}
}

func observeTieredVolume(t *testing.T, h managerHarness, cellID, requestID string, observation VolumeObservation) {
	t.Helper()
	observeTieredCell(t, h, cellID, requestID, true, observation)
}

// observeTieredCell is the full-fidelity observation: a cell must report every
// volume assigned to it on every pass, and its archive capability with them.
func observeTieredCell(t *testing.T, h managerHarness, cellID, requestID string, archiveConfigured bool, observations ...VolumeObservation) {
	t.Helper()
	plan := verifiedPlan(t, h.manager, cellID, *h.now)
	_, err := h.manager.ObserveCell(requestID, CellObservation{CellID: cellID, PlanGeneration: plan.Generation, ManagerReleaseID: h.manager.ReleaseIdentity(),
		AgentReleaseID: "agent-v2", HelperReleaseID: "helper-v2", ObservedUnix: h.now.Unix(), PlanVersions: []uint32{1, 2},
		HelperPlanVersions: []uint32{1, 2}, HelperStateVersions: []uint32{1, 2}, ArchiveConfigured: archiveConfigured,
		Volumes: observations})
	if err != nil {
		t.Fatal(err)
	}
}

// storeVolume reads durable state: the product view sanitizes the archive
// record, so record-level assertions are made at the store.
func storeVolume(t *testing.T, h managerHarness, volumeID string) Volume {
	t.Helper()
	var volume Volume
	if err := h.store.View(func(state State) error {
		stored, ok := state.Volumes[volumeID]
		if !ok {
			t.Fatalf("volume %s is absent from durable state", volumeID)
		}
		volume = stored
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return volume
}

func TestArchiveRefusedWithoutAVerifierOrAnArchiveCapableCell(t *testing.T) {
	h := newManagerHarness(t)
	cell, volume := readyVolumeForMount(t, h)
	before := verifiedPlan(t, h.manager, cell.ID, *h.now).Generation
	// A Manager with no archive credentials can never verify the seal it would
	// be waiting for, so the cycle is refused before the volume stops serving —
	// and refused as unsupported, not busy: a client must be able to tell a
	// deployment that cannot archive from one that is momentarily loaded.
	if _, err := h.manager.ArchiveVolume("archive-no-verifier", ArchiveVolumeRequest{VolumeID: volume.ID}); !errors.Is(err, ErrArchiveUnsupported) {
		t.Fatalf("archive without a verifier = %v", err)
	}
	unchanged, _ := h.manager.GetVolume(volume.ID)
	if unchanged.State != VolumeReady || unchanged.ArchiveCycleStep != "" || unchanged.ArchiveAttempt != "" {
		t.Fatalf("refused archive changed volume state = %+v", unchanged)
	}
	if after := verifiedPlan(t, h.manager, cell.ID, *h.now).Generation; after != before {
		t.Fatalf("refused archive bumped the plan %d -> %d", before, after)
	}

	h.manager.cfg.ArchiveVerifier = &fakeArchiveVerifier{}
	ready := VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID,
		ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
		Provisioned: true, AuthorityRunning: true}
	// A cell whose helper holds no usable archive credentials can neither export
	// nor hydrate; archive work is never placed on it.
	observeTieredCell(t, h, cell.ID, "archive-capability-lost", false, ready)
	if _, err := h.manager.ArchiveVolume("archive-incapable-cell", ArchiveVolumeRequest{VolumeID: volume.ID}); !errors.Is(err, ErrArchiveUnsupported) {
		t.Fatalf("archive on an archive-incapable cell = %v", err)
	}
	observeTieredCell(t, h, cell.ID, "archive-capability-restored", true, ready)
	if archiving, err := h.manager.ArchiveVolume("archive-capable-cell", ArchiveVolumeRequest{VolumeID: volume.ID}); err != nil ||
		archiving.State != VolumeArchiving {
		t.Fatalf("archive on a capable cell = %+v, %v", archiving, err)
	}
}

func TestSealCapturesMeasuredUsageAndRaisesTheRestoreCharge(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.ArchiveVerifier = &fakeArchiveVerifier{}
	cell, volume := readyVolumeForMount(t, h)
	const measuredBytes, measuredInodes = 900 << 20, 4321
	archiving, err := h.manager.ArchiveVolume("measured-archive", ArchiveVolumeRequest{VolumeID: volume.ID})
	if err != nil {
		t.Fatal(err)
	}
	observeTieredVolume(t, h, cell.ID, "measured-quiesced", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: archiving.AuthorityEpoch,
		ProjectID: archiving.Placement.ProjectID, ServiceUID: archiving.Placement.ServiceUID, ServiceGID: archiving.Placement.ServiceGID,
		ListenPort: archiving.Placement.ListenPort, Provisioned: true, AuthorityAbsent: true, QuiesceProven: true,
		UsedBytes: measuredBytes, UsedInodes: measuredInodes})
	exporting, _ := h.manager.GetVolume(volume.ID)
	seal := validArchiveSeal(exporting.ArchiveAttempt)
	observeTieredVolume(t, h, cell.ID, "measured-sealed", VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: exporting.AuthorityEpoch,
		ProjectID: exporting.Placement.ProjectID, ServiceUID: exporting.Placement.ServiceUID, ServiceGID: exporting.Placement.ServiceGID,
		ListenPort: exporting.Placement.ListenPort, Provisioned: true, AuthorityAbsent: true, ArchiveSealed: &seal,
		UsedBytes: measuredBytes, UsedInodes: measuredInodes})
	// The pending seal carries only what the cell reported; the measurement is
	// attached by the Manager at the moment the verified seal commits.
	if pending := storeVolume(t, h, volume.ID).PendingSeal; pending == nil || pending.SealedMeasuredBytes != 0 || pending.SealedMeasuredInodes != 0 {
		t.Fatalf("pending seal carried a measurement = %+v", pending)
	}
	if err := h.manager.NoteVerify(volume.ID); err != nil {
		t.Fatal(err)
	}
	record := storeVolume(t, h, volume.ID).Archive
	if record == nil || record.SealedMeasuredBytes != measuredBytes || record.SealedMeasuredInodes != measuredInodes {
		t.Fatalf("committed archive record = %+v", record)
	}
	// The archive's own sizing (8 KiB of packed extents here) understates the
	// tree the restore has to land; admission charges the measured base.
	bytes, inodes, err := h.manager.restoreCharge(*record)
	wantBytes := uint64(measuredBytes) + uint64(float64(measuredBytes)*h.manager.cfg.RestoreOverheadFraction+0.999999) + h.manager.cfg.RestoreOverheadBytes
	if err != nil || bytes != wantBytes || inodes != measuredInodes+h.manager.cfg.RestoreOverheadInodes {
		t.Fatalf("restore charge = %d, %d, %v (want %d)", bytes, inodes, err, wantBytes)
	}
	// A record sealed before the field existed decodes zero and must still
	// charge the archive's own sizing.
	unmeasured := *record
	unmeasured.SealedMeasuredBytes, unmeasured.SealedMeasuredInodes = 0, 0
	if err := unmeasured.Validate(); err != nil {
		t.Fatalf("unmeasured record validity = %v", err)
	}
	legacyBytes, legacyInodes, err := h.manager.restoreCharge(unmeasured)
	if err != nil || legacyBytes >= bytes || legacyInodes >= inodes || legacyBytes < record.SealedAllocatedBytes {
		t.Fatalf("unmeasured restore charge = %d, %d, %v", legacyBytes, legacyInodes, err)
	}
}

func TestWakePropagatesRestoreConcurrencySaturationAsRetryableBusy(t *testing.T) {
	h := newManagerHarness(t)
	h.manager.cfg.MaxRestoringPerCell = 1
	cell, volume := readyVolumeForMount(t, h)
	occupant, err := h.manager.CreateVolume("busy-occupant", CreateVolumeRequest{AuthorizationDomain: "org", Owner: "owner",
		ProductIssuer: "opensteer", QuotaBytes: 1 << 30, QuotaInodes: 10_000, Pool: PoolProduct})
	if err != nil {
		t.Fatal(err)
	}
	// Creating the occupant bumped the cell plan; admission needs a heartbeat at
	// the current generation, which only a fresh observation supplies.
	observeTieredCell(t, h, cell.ID, "busy-observe", true,
		VolumeObservation{VolumeID: volume.ID, AuthorityGeneration: volume.AuthorityEpoch, ProjectID: volume.Placement.ProjectID,
			ServiceUID: volume.Placement.ServiceUID, ServiceGID: volume.Placement.ServiceGID, ListenPort: volume.Placement.ListenPort,
			Provisioned: true, AuthorityRunning: true},
		VolumeObservation{VolumeID: occupant.ID, AuthorityGeneration: occupant.AuthorityEpoch, ProjectID: occupant.Placement.ProjectID,
			ServiceUID: occupant.Placement.ServiceUID, ServiceGID: occupant.Placement.ServiceGID, ListenPort: occupant.Placement.ListenPort,
			Provisioned: true})
	seal := validArchiveSeal("33333333-3333-4333-8333-333333333333")
	sealed, err := archiveRecordFromObservation(Volume{ArchiveAttempt: seal.Attempt, AuthorityEpoch: volume.AuthorityEpoch}, &seal, h.now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	// The waker is placement-free ARCHIVED; the occupant already holds the
	// cell's only restore slot.
	if _, err := h.store.TransactNatural("seed-busy-restore", h.now.Unix(), func(state *State) (any, bool, error) {
		waker := state.Volumes[volume.ID]
		waker.State, waker.Placement, waker.Archive, waker.ArchiveCycleStep = VolumeArchived, nil, &sealed, "released"
		waker.UpdatedUnix = h.now.Unix()
		state.Volumes[waker.ID] = waker
		restoring := state.Volumes[occupant.ID]
		occupantSeal := sealed
		occupantSeal.SealedEpoch = 1
		restoring.AuthorityEpoch = 2
		restoring.State, restoring.Archive, restoring.ArchiveCycleStep, restoring.RestoreStep = VolumeRestoring, &occupantSeal, "released", "restoring-namespace"
		restoring.UpdatedUnix = h.now.Unix()
		state.Volumes[restoring.ID] = restoring
		return nil, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.WakeVolume("wake-busy", WakeVolumeRequest{VolumeID: volume.ID}); !errors.Is(err, ErrBusy) {
		t.Fatalf("wake against a saturated cell = %v", err)
	}
	if refused, _ := h.manager.GetVolume(volume.ID); refused.State != VolumeArchived || refused.Placement != nil || refused.PlacementSequence != 1 {
		t.Fatalf("busy wake changed state = %+v", refused)
	}
	h.manager.cfg.MaxRestoringPerCell = 2
	woken, err := h.manager.WakeVolume("wake-after-slot", WakeVolumeRequest{VolumeID: volume.ID})
	if err != nil || woken.State != VolumeRestoring || woken.Placement == nil || woken.Placement.CellID != cell.ID {
		t.Fatalf("wake after a slot freed = %+v, %v", woken, err)
	}
}

func validArchiveSeal(attempt string) ArchiveSealedObservation {
	return ArchiveSealedObservation{Attempt: attempt, FormatVersion: 1, ChunkSizeBytes: 8 << 20, KeyVersion: "default",
		Manifest: ObjectRef{Key: "volume/manifest", SizeBytes: 4096, SHA256: strings.Repeat("a", 64)},
		Packs:    []ObjectRef{{Key: "volume/pack-0", SizeBytes: 8192, SHA256: strings.Repeat("b", 64)}}, RootDigest: strings.Repeat("c", 64),
		LogicalBytes: 1024, LogicalInodes: 2, SealedAllocatedBytes: 8192, SealedInodes: 2}
}

// storeHasPendingSeal inspects durable state: the product view is sanitized
// and never carries the pending seal, so tests assert it at the store.
func storeHasPendingSeal(t *testing.T, h managerHarness, volumeID string) bool {
	t.Helper()
	var present bool
	if err := h.store.View(func(state State) error {
		volume, ok := state.Volumes[volumeID]
		present = ok && volume.PendingSeal != nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return present
}
