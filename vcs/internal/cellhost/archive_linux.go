//go:build linux

package cellhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
	"github.com/steerlabs/portablefs/vcs/internal/cellhelper"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"golang.org/x/sys/unix"
)

func (host *Host) WriteArchiverConfig(plan cellplan.VolumePlan) error {
	if plan.ArchiveTo == nil || !cellplan.ValidID(plan.VolumeID) {
		return ErrInvalid
	}
	config := ArchiverConfig{Version: 1, VolumeID: plan.VolumeID, CellID: host.cfg.CellID,
		AuthorityEpoch: plan.AuthorityGeneration, PlacementSequence: placementSequenceOf(plan),
		Attempt: plan.ArchiveTo.Attempt, KeyVersion: plan.ArchiveTo.KeyVersion, ChunkSizeBytes: host.cfg.ArchiveChunkSizeBytes}
	return host.writeLaunchConfig(plan.VolumeID, plan.ServiceGID, archiveConfigName, config)
}

func (host *Host) WriteHydratorConfig(plan cellplan.VolumePlan, mode HydratorMode) error {
	if plan.RestoreFrom == nil || !validHydratorMode(mode) || !cellplan.ValidID(plan.VolumeID) {
		return ErrInvalid
	}
	source := plan.RestoreFrom
	config := HydratorConfig{Version: 1, VolumeID: plan.VolumeID, CellID: host.cfg.CellID,
		SealedEpoch: source.SealedEpoch, Attempt: source.Attempt, Mode: mode,
		ManifestSHA256: source.ManifestDigestSHA256, ManifestSizeBytes: source.ManifestSizeBytes,
		ManifestCRC64NVME: source.ManifestCRC64NVME, ChunkSizeBytes: host.cfg.ArchiveChunkSizeBytes}
	return host.writeLaunchConfig(plan.VolumeID, plan.ServiceGID, hydratorConfigName, config)
}

func (host *Host) writeLaunchConfig(volumeID string, serviceGID uint32, name string, config any) error {
	if serviceGID < 1000 {
		return ErrInvalid
	}
	payload, err := json.Marshal(config)
	if err != nil || len(payload) > maxLaunchConfigBytes {
		return errors.New("cellhost: launch configuration exceeds its bound")
	}
	directory := filepath.Join(host.cfg.ConfigRoot, volumeID)
	if err := ensureManagedDirectory(directory, 0, int(serviceGID), 0o750); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(directory, name), payload, 0, int(serviceGID), 0o440)
}

// ArchiveConfigured reports whether this cell can do archive or restore work at
// all. A false answer keeps the Manager from placing export or hydration work
// here, so the answer has to mean what the archiver and the hydrator will find
// when they get here: it parses the credentials with the same loader they use
// on the staged copy (archivestore.LoadConfigFile), which pins the file's shape
// - regular, unreadable by group and other, bounded - and its content, down to
// every required key being present and every value addressable. A file that is
// merely present admits a full archive cycle that can only fail at the far end,
// long after the operator who could have fixed it stopped looking.
//
// This runs on every status pass. Reading and parsing a small private file is
// what that costs; nothing here touches the network. Whether the store is
// actually reachable belongs to the archive attempt, which has wake-cancel as
// its recovery, and a reachability probe on the status path would turn a
// transient outage into an unplaceable cell.
func (host *Host) ArchiveConfigured() bool {
	if host.cfg.ArchiveCredentialsPath == "" {
		return false
	}
	_, err := archivestore.LoadConfigFile(host.cfg.ArchiveCredentialsPath)
	return err == nil
}

// stageArchiveCredentials copies the root-provisioned cell credentials into
// the volume's ConfigRoot as root:<serviceGID> 0440, exactly like every other
// per-volume config file. The unit binds this copy: binding the shared
// root-owned file directly would leave the service UID unable to read it, and
// loosening the shared file's mode would expose credentials to every local
// account on the cell.
func (host *Host) stageArchiveCredentials(volumeID string, serviceGID uint32) (string, error) {
	raw, err := readPrivate(host.cfg.ArchiveCredentialsPath)
	if err != nil {
		return "", fmt.Errorf("cellhost: archive credentials: %w", err)
	}
	staged := filepath.Join(host.cfg.ConfigRoot, volumeID, "archive-credentials.env")
	if err := writeAtomic(staged, raw, 0, int(serviceGID), 0o440); err != nil {
		return "", err
	}
	return staged, nil
}

func (host *Host) WriteArchiverDropIns(plan cellplan.VolumePlan) error {
	if !cellplan.ValidID(plan.VolumeID) || plan.ServiceUID < 1000 || plan.ServiceGID < 1000 {
		return ErrInvalid
	}
	resultPath := filepath.Join(host.cfg.StateRoot, plan.VolumeID, archiveResultDirectoryName)
	if err := ensureManagedDirectory(resultPath, int(plan.ServiceUID), int(plan.ServiceGID), 0o700); err != nil {
		return err
	}
	credentials, err := host.stageArchiveCredentials(plan.VolumeID, plan.ServiceGID)
	if err != nil {
		return err
	}
	content := fmt.Sprintf("[Service]\nUser=%d\nGroup=%d\nBindReadOnlyPaths=%s:/srv/portablefs-volume\nBindReadOnlyPaths=%s:/run/portablefs-volume\nBindReadOnlyPaths=%s:%s\nBindPaths=%s:/var/lib/portablefs-volume-archive\n",
		plan.ServiceUID, plan.ServiceGID, filepath.Join(host.cfg.CellRoot, plan.VolumeID), filepath.Join(host.cfg.ConfigRoot, plan.VolumeID),
		credentials, archiveCredentialsServicePath, resultPath)
	return host.writeUnitDropIn(archiverUnit(plan.VolumeID), content)
}

func (host *Host) WriteHydratorDropIns(plan cellplan.VolumePlan, mode HydratorMode) error {
	if !cellplan.ValidID(plan.VolumeID) || plan.ServiceUID < 1000 || plan.ServiceGID < 1000 || !validHydratorMode(mode) {
		return ErrInvalid
	}
	statePath := filepath.Join(host.cfg.StateRoot, plan.VolumeID)
	if err := ensureManagedDirectory(statePath, int(plan.ServiceUID), int(plan.ServiceGID), 0o700); err != nil {
		return err
	}
	credentials, err := host.stageArchiveCredentials(plan.VolumeID, plan.ServiceGID)
	if err != nil {
		return err
	}
	content := fmt.Sprintf("[Service]\nUser=%d\nGroup=%d\nBindPaths=%s:/var/lib/portablefs-volume\nBindReadOnlyPaths=%s:/run/portablefs-volume\nBindReadOnlyPaths=%s:%s\n",
		plan.ServiceUID, plan.ServiceGID, statePath, filepath.Join(host.cfg.ConfigRoot, plan.VolumeID),
		credentials, archiveCredentialsServicePath)
	if mode == HydratorModeRestoreNamespace {
		content += fmt.Sprintf("BindPaths=%s:/srv/portablefs-volume\n", filepath.Join(host.cfg.CellRoot, plan.VolumeID))
	}
	return host.writeUnitDropIn(hydratorUnit(plan.VolumeID), content)
}

func (host *Host) writeUnitDropIn(unit, content string) error {
	directory := filepath.Join(host.cfg.SystemdUnitRoot, unit+".d")
	if err := ensureManagedDirectory(directory, 0, 0, 0o755); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(directory, "10-portablefs.conf"), []byte(content), 0, 0, 0o644)
}

func (host *Host) StartArchiver(ctx context.Context, volumeID string) error {
	return host.startWorker(ctx, archiverUnit(volumeID), "archiver")
}

func (host *Host) StopArchiver(ctx context.Context, volumeID string) error {
	return host.stopWorker(ctx, archiverUnit(volumeID), "archiver")
}

func (host *Host) ArchiverAbsent(ctx context.Context, volumeID string) (bool, error) {
	return host.workerAbsent(ctx, archiverUnit(volumeID), "archiver")
}

func (host *Host) StartHydrator(ctx context.Context, volumeID string, mode HydratorMode) error {
	if !validHydratorMode(mode) {
		return ErrInvalid
	}
	return host.startWorker(ctx, hydratorUnit(volumeID), "hydrator")
}

func (host *Host) StopHydrator(ctx context.Context, volumeID string) error {
	return host.stopWorker(ctx, hydratorUnit(volumeID), "hydrator")
}

func (host *Host) HydratorAbsent(ctx context.Context, volumeID string) (bool, error) {
	return host.workerAbsent(ctx, hydratorUnit(volumeID), "hydrator")
}

func (host *Host) startWorker(ctx context.Context, unit, kind string) error {
	for _, arguments := range [][]string{{"daemon-reload"}, {"start", unit}} {
		if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, arguments...); err != nil {
			return commandError("start "+kind, output, err)
		}
	}
	if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "is-active", "--quiet", unit); err != nil {
		return commandError("verify "+kind+" active", output, err)
	}
	return nil
}

func (host *Host) stopWorker(ctx context.Context, unit, kind string) error {
	_, _ = host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "kill", "--kill-whom=all", "--signal=SIGKILL", unit)
	if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "stop", unit); err != nil {
		return commandError("stop "+kind, output, err)
	}
	absent, err := host.workerAbsent(ctx, unit, kind)
	if err != nil {
		return err
	}
	if !absent {
		return fmt.Errorf("cellhost: %s remained active after stop", kind)
	}
	return nil
}

func (host *Host) workerAbsent(ctx context.Context, unit, kind string) (bool, error) {
	if _, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "is-active", "--quiet", unit); err == nil {
		// Named by unit, not just kind: refusal messages are the operator's
		// only pointer to which per-volume worker is still alive.
		return false, fmt.Errorf("cellhost: %s (%s) unit is active", unit, kind)
	}
	output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "show", "--property=ControlGroup", "--value", unit)
	if err != nil {
		return false, commandError("inspect "+kind+" cgroup", output, err)
	}
	controlGroup := strings.TrimSpace(string(output))
	if controlGroup != "" && controlGroup != "/" {
		eventsPath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(controlGroup, "/"), "cgroup.events")
		events, readErr := os.ReadFile(eventsPath)
		if readErr == nil && !strings.Contains(string(events), "populated 0") {
			return false, fmt.Errorf("cellhost: %s cgroup is still populated", kind)
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return false, readErr
		}
	}
	return true, nil
}

func (host *Host) RemoveArchiverDropIns(ctx context.Context, volumeID string) error {
	return host.removeWorkerDropIns(ctx, archiverUnit(volumeID))
}

func (host *Host) RemoveHydratorDropIns(ctx context.Context, volumeID string) error {
	return host.removeWorkerDropIns(ctx, hydratorUnit(volumeID))
}

func (host *Host) removeWorkerDropIns(ctx context.Context, unit string) error {
	if err := removeTreeBeneath(host.cfg.SystemdUnitRoot, unit+".d"); err != nil {
		return err
	}
	if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "daemon-reload"); err != nil {
		return commandError("reload systemd after removing worker drop-ins", output, err)
	}
	return nil
}

func (host *Host) RemoveArchiverConfig(volumeID string) error {
	return removeTreeBeneath(filepath.Join(host.cfg.ConfigRoot, volumeID), archiveConfigName)
}

func (host *Host) RemoveHydratorConfig(volumeID string) error {
	return removeTreeBeneath(filepath.Join(host.cfg.ConfigRoot, volumeID), hydratorConfigName)
}

func (host *Host) ReadArchiveSealed(volumeID string) (ArchiveSealedRecord, error) {
	var record ArchiveSealedRecord
	path := filepath.Join(host.cfg.StateRoot, volumeID, archiveResultDirectoryName, archiveSealedName)
	if err := readResult(path, maxArchiveSealedBytes, ErrArchiveSealedAbsent, &record); err != nil {
		return ArchiveSealedRecord{}, err
	}
	if err := validateArchiveSealed(record, volumeID, host.cfg.CellID); err != nil {
		return ArchiveSealedRecord{}, err
	}
	return record, nil
}

func (host *Host) ReadRestoreNamespaceReady(volumeID string) (RestoreNamespaceReadyRecord, error) {
	var record RestoreNamespaceReadyRecord
	path := filepath.Join(host.cfg.StateRoot, volumeID, archiveResultDirectoryName, restoreNamespaceReadyName)
	if err := readResult(path, maxRestoreResultBytes, ErrRestoreNamespaceReadyAbsent, &record); err != nil {
		return RestoreNamespaceReadyRecord{}, err
	}
	if record.Version != 1 || record.VolumeID != volumeID || record.SealedEpoch == 0 || !cellplan.ValidID(record.Attempt) || record.Entries == 0 || record.WrittenUnix <= 0 {
		return RestoreNamespaceReadyRecord{}, errors.New("cellhost: restore namespace-ready record is invalid")
	}
	return record, nil
}

func (host *Host) ReadRestoreProgress(volumeID string) (RestoreProgressRecord, error) {
	var record RestoreProgressRecord
	if err := readResult(filepath.Join(host.cfg.StateRoot, volumeID, restoreProgressName), maxRestoreResultBytes, ErrRestoreProgressAbsent, &record); err != nil {
		return RestoreProgressRecord{}, err
	}
	if record.Version != 1 || record.ProgressPermille > 1000 ||
		record.State != "" && record.State != "blocked" && record.State != "corrupt" || record.UpdatedUnix <= 0 {
		return RestoreProgressRecord{}, errors.New("cellhost: restore progress record is invalid")
	}
	return record, nil
}

func (host *Host) ReadRestoreConverged(volumeID string) (RestoreConvergedRecord, error) {
	var record RestoreConvergedRecord
	if err := readResult(filepath.Join(host.cfg.StateRoot, volumeID, restoreConvergedName), maxRestoreResultBytes, ErrRestoreConvergedAbsent, &record); err != nil {
		return RestoreConvergedRecord{}, err
	}
	if record.Version != 1 || record.VolumeID != volumeID || record.AuthorityEpoch == 0 || !cellplan.ValidID(record.Attempt) || record.WrittenUnix <= 0 {
		return RestoreConvergedRecord{}, errors.New("cellhost: restore convergence record is invalid")
	}
	return record, nil
}

func readResult(path string, limit int64, absent error, target any) error {
	if !safeRoot(path) || limit <= 0 {
		return ErrInvalid
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%w: %s", absent, filepath.Base(path))
		}
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return syscall.EBADF
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0o022 != 0 {
		return errors.New("cellhost: result record must be a bounded non-writable regular file")
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(payload)) > limit {
		return errors.New("cellhost: result record exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("cellhost: result record has trailing data")
	}
	return nil
}

func (host *Host) applyArchive(ctx context.Context, plan cellplan.VolumePlan, previous cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	observed, update := host.applyQuiesceFence(ctx, plan, previous)
	if observed.Error != "" || !observed.AuthorityAbsent || !observed.QuiesceProven {
		return observed, update
	}
	archived, archiveUpdate := host.observeArchive(ctx, plan, previous)
	if archiveUpdate.ArchiveSealed != nil {
		update.ArchiveSealed = archiveUpdate.ArchiveSealed
	}
	return archived, update
}

func (host *Host) observeArchive(ctx context.Context, plan cellplan.VolumePlan, previous cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	observed := host.observeQuiesceFence(ctx, plan, previous)
	if observed.Error != "" {
		return observed, cellhelper.HostUpdate{}
	}
	var err error
	record, err := host.ReadArchiveSealed(plan.VolumeID)
	if err == nil {
		if plan.ArchiveTo == nil || record.Attempt != plan.ArchiveTo.Attempt || record.SealedEpoch != plan.AuthorityGeneration ||
			record.KeyVersion != plan.ArchiveTo.KeyVersion || record.ChunkSizeBytes != host.cfg.ArchiveChunkSizeBytes {
			observed.Error = "cellhost: archive seal does not match the signed archive attempt"
			return observed, cellhelper.HostUpdate{}
		}
		if stopErr := host.StopArchiver(ctx, plan.VolumeID); stopErr != nil {
			observed.Error = stopErr.Error()
			return observed, cellhelper.HostUpdate{}
		}
		observed.ArchiveSealed = record.Observation()
		return observed, cellhelper.HostUpdate{ArchiveSealed: record.Observation()}
	}
	if !errors.Is(err, ErrArchiveSealedAbsent) {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if err := host.WriteArchiverConfig(plan); err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if err := host.WriteArchiverDropIns(plan); err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if err := host.StartArchiver(ctx, plan.VolumeID); err != nil {
		observed.Error = err.Error()
	}
	return observed, cellhelper.HostUpdate{}
}

func (host *Host) applyRestore(ctx context.Context, plan cellplan.VolumePlan, previous cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	observed := controlplane.VolumeObservation{}
	var err error
	observed.Provisioned, observed.AuthorityCSRPEM, err = host.provision(ctx, plan,
		signedQuota{Bytes: plan.QuotaBytes, Inodes: plan.QuotaInodes}, appliedQuota{Bytes: previous.AppliedQuotaBytes, Inodes: previous.AppliedQuotaInodes})
	if err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	ready, err := host.ReadRestoreNamespaceReady(plan.VolumeID)
	if errors.Is(err, ErrRestoreNamespaceReadyAbsent) {
		if err := host.WriteHydratorConfig(plan, HydratorModeRestoreNamespace); err != nil {
			observed.Error = err.Error()
			return observed, cellhelper.HostUpdate{}
		}
		if err := host.WriteHydratorDropIns(plan, HydratorModeRestoreNamespace); err != nil {
			observed.Error = err.Error()
			return observed, cellhelper.HostUpdate{}
		}
		if err := host.StartHydrator(ctx, plan.VolumeID, HydratorModeRestoreNamespace); err != nil {
			observed.Error = err.Error()
		}
		observed.AuthorityAbsent = true
		return observed, cellhelper.HostUpdate{}
	}
	if err != nil || plan.RestoreFrom == nil || ready.Attempt != plan.RestoreFrom.Attempt || ready.SealedEpoch != plan.RestoreFrom.SealedEpoch {
		if err == nil {
			err = errors.New("cellhost: namespace-ready record does not match the signed restore source")
		}
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if plan.AuthorityCertificate == "" {
		// The landed Manager obtains proof of possession from the first RESTORE
		// observation, then emits the certificate on the next plan generation.
		// Do not publish namespace-ready early: Manager treats that signal as the
		// same-pass serving gate and requires AuthorityRunning with it.
		observed.AuthorityAbsent = true
		return observed, cellhelper.HostUpdate{}
	}
	if err := host.StopHydrator(ctx, plan.VolumeID); err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if err := host.WriteHydratorConfig(plan, HydratorModeServe); err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if err := host.WriteHydratorDropIns(plan, HydratorModeServe); err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if err := host.StartHydrator(ctx, plan.VolumeID, HydratorModeServe); err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	if err := host.start(ctx, plan); err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	observed.RestoreNamespaceReady, observed.AuthorityRunning = true, true
	host.readRestoreStatus(plan, &observed)
	return observed, cellhelper.HostUpdate{}
}

func (host *Host) observeRestore(ctx context.Context, plan cellplan.VolumePlan) controlplane.VolumeObservation {
	observed := controlplane.VolumeObservation{}
	provisioned, csr, err := host.observeProvisioned(plan)
	observed.Provisioned, observed.AuthorityCSRPEM = provisioned, csr
	if err != nil {
		observed.Error = err.Error()
		return observed
	}
	ready, err := host.ReadRestoreNamespaceReady(plan.VolumeID)
	if err != nil || plan.RestoreFrom == nil || ready.Attempt != plan.RestoreFrom.Attempt || ready.SealedEpoch != plan.RestoreFrom.SealedEpoch {
		if err == nil {
			err = errors.New("cellhost: namespace-ready record does not match the signed restore source")
		}
		observed.Error = err.Error()
		return observed
	}
	observed.RestoreNamespaceReady = true
	observed.AuthorityRunning = host.unitActive(ctx, authorityServiceUnit(plan.VolumeID))
	if !observed.AuthorityRunning {
		observed.AuthorityAbsent = true
	}
	if !host.unitActive(ctx, hydratorUnit(plan.VolumeID)) {
		observed.Error = "cellhost: restore hydrator is absent while restore is serving"
		return observed
	}
	host.readRestoreStatus(plan, &observed)
	return observed
}

func (host *Host) readRestoreStatus(plan cellplan.VolumePlan, observed *controlplane.VolumeObservation) {
	if progress, err := host.ReadRestoreProgress(plan.VolumeID); err == nil {
		observed.RestoreProgressPermille, observed.RestoreState = progress.ProgressPermille, progress.State
	} else if !errors.Is(err, ErrRestoreProgressAbsent) {
		observed.Error = err.Error()
		return
	}
	if converged, err := host.ReadRestoreConverged(plan.VolumeID); err == nil {
		if plan.RestoreFrom == nil || converged.Attempt != plan.RestoreFrom.Attempt || converged.AuthorityEpoch != plan.AuthorityGeneration {
			observed.Error = "cellhost: convergence record does not match the current restore"
			return
		}
		observed.RestoreConverged = true
	} else if !errors.Is(err, ErrRestoreConvergedAbsent) {
		observed.Error = err.Error()
	}
}

func (host *Host) cleanupConvergedHydrator(ctx context.Context, plan cellplan.VolumePlan) error {
	converged, err := host.ReadRestoreConverged(plan.VolumeID)
	if err != nil {
		return fmt.Errorf("cellhost: serve after restore lacks convergence proof: %w", err)
	}
	if converged.AuthorityEpoch != plan.AuthorityGeneration {
		return errors.New("cellhost: convergence proof belongs to another authority epoch")
	}
	if err := host.StopHydrator(ctx, plan.VolumeID); err != nil {
		return err
	}
	if err := host.RemoveHydratorConfig(plan.VolumeID); err != nil {
		return err
	}
	return host.RemoveHydratorDropIns(ctx, plan.VolumeID)
}

func (host *Host) applyDestroy(ctx context.Context, plan cellplan.VolumePlan, previous cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	observed := controlplane.VolumeObservation{AuthorityAbsent: true}
	for _, check := range []func(context.Context, string) (bool, error){host.ArchiverAbsent, host.HydratorAbsent} {
		absent, err := check(ctx, plan.VolumeID)
		if err != nil || !absent {
			if err == nil {
				err = errors.New("cellhost: destroy requires archiver and hydrator absence")
			}
			observed.Error = err.Error()
			return observed, cellhelper.HostUpdate{}
		}
	}
	result, err := host.Destroy(ctx, DestroyInput{VolumeID: previous.VolumeID, AuthorityID: previous.AuthorityID,
		AuthorityServerName: previous.AuthorityServerName, AuthorityEpoch: previous.AuthorityGeneration,
		PlacementSequence: previous.PlacementSequence, ProjectID: previous.ProjectID, ServiceUID: previous.ServiceUID,
		ServiceGID: previous.ServiceGID, ListenPort: previous.ListenPort,
		QuotaWasApplied: previous.AppliedQuotaBytes != 0 || previous.AppliedQuotaInodes != 0})
	if err != nil {
		observed.Error = err.Error()
		return observed, cellhelper.HostUpdate{}
	}
	proof := &cellhelper.DestroyProof{SHA256: result.ProofSHA256, Record: cellhelper.DestroyRecord{
		AuthorityEpoch: result.Record.AuthorityEpoch, AuthorityID: result.Record.AuthorityID,
		AuthorityServerName: result.Record.AuthorityServerName, CellID: result.Record.CellID,
		ListenPort: result.Record.ListenPort, PlacementSequence: result.Record.PlacementSequence,
		Postconditions: cellhelper.DestroyPostconditions{ConfigRootAbsent: result.Record.Postconditions.ConfigRootAbsent,
			DropInsAbsent: result.Record.Postconditions.DropInsAbsent, QuotaCleared: result.Record.Postconditions.QuotaCleared,
			StateRootAbsent: result.Record.Postconditions.StateRootAbsent, SysusersConfAbsent: result.Record.Postconditions.SysusersConfAbsent,
			TreeAbsent: result.Record.Postconditions.TreeAbsent}, ProjectID: result.Record.ProjectID,
		ServiceGID: result.Record.ServiceGID, ServiceUID: result.Record.ServiceUID, VolumeID: result.Record.VolumeID}}
	observed.DestroyProofSHA256 = proof.SHA256
	return observed, cellhelper.HostUpdate{DestroyProof: proof}
}

func (host *Host) measureForPhase(phase cellplan.VolumePhase, volumeID string, observed *controlplane.VolumeObservation) {
	switch phase {
	case cellplan.PhaseProvision, cellplan.PhaseServe, cellplan.PhaseRestore:
		bytes, inodes, err := host.MeasureUsage(volumeID)
		if err != nil {
			if observed.Error == "" {
				observed.Error = err.Error()
			}
			return
		}
		observed.UsedBytes, observed.UsedInodes = bytes, inodes
	}
}

func (host *Host) unitActive(ctx context.Context, unit string) bool {
	_, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "is-active", "--quiet", unit)
	return err == nil
}

func placementSequenceOf(plan cellplan.VolumePlan) uint64 {
	if plan.PlacementSequence == 0 {
		return 1
	}
	return plan.PlacementSequence
}
