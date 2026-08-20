//go:build !linux

package cellhost

import (
	"context"
	"errors"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellhelper"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

type CommandRunner interface{}
type ExecRunner struct{}

type Config struct {
	CellID, CellRoot, ConfigRoot, StateRoot, SystemdUnitRoot, SysusersRoot string
	ArchiveCredentialsPath                                                 string
	ArchiveChunkSizeBytes                                                  uint32
	XFSQuotaBinary, SystemctlBinary, SystemdRunBinary, SysusersBinary      string
	Runner                                                                 CommandRunner
	Now                                                                    func() time.Time
}

type Host struct{}

func New(Config) (*Host, error) { return nil, errors.New("cellhost: supported only on Linux") }

func (*Host) Apply(_ context.Context, _ cellplan.VolumePlan, _ cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	return controlplane.VolumeObservation{Error: "cellhost: supported only on Linux"}, cellhelper.HostUpdate{}
}

func (*Host) Observe(_ context.Context, _ cellplan.VolumePlan, _ cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	return controlplane.VolumeObservation{Error: "cellhost: supported only on Linux"}, cellhelper.HostUpdate{}
}

// The tiered-storage host operations exist here only so the package presents
// one API on every platform. They are XFS, systemd, and openat2 operations;
// there is no meaningful non-Linux behavior to fall back to, and each refuses
// rather than pretending to have measured or destroyed anything.

var errNotLinux = errors.New("cellhost: supported only on Linux")

func (*Host) MeasureUsage(string) (uint64, uint64, error) { return 0, 0, errNotLinux }

func (*Host) StrictMembershipEmpty(string) (bool, error) { return false, errNotLinux }

func (*Host) Destroy(context.Context, DestroyInput) (DestroyResult, error) {
	return DestroyResult{}, errNotLinux
}

func (*Host) WriteQuiesceRequest(string, uint32) (string, error) { return "", errNotLinux }

func (*Host) ClearQuiesceRequest(string) error { return errNotLinux }

func (*Host) ReadQuiesceProof(string) (QuiesceProof, error) { return QuiesceProof{}, errNotLinux }

func (*Host) WriteArchiverConfig(cellplan.VolumePlan) error                { return errNotLinux }
func (*Host) WriteHydratorConfig(cellplan.VolumePlan, HydratorMode) error  { return errNotLinux }
func (*Host) WriteArchiverDropIns(cellplan.VolumePlan) error               { return errNotLinux }
func (*Host) WriteHydratorDropIns(cellplan.VolumePlan, HydratorMode) error { return errNotLinux }
func (*Host) StartArchiver(context.Context, string) error                  { return errNotLinux }
func (*Host) StopArchiver(context.Context, string) error                   { return errNotLinux }
func (*Host) ArchiverAbsent(context.Context, string) (bool, error)         { return false, errNotLinux }
func (*Host) StartHydrator(context.Context, string, HydratorMode) error    { return errNotLinux }
func (*Host) StopHydrator(context.Context, string) error                   { return errNotLinux }
func (*Host) HydratorAbsent(context.Context, string) (bool, error)         { return false, errNotLinux }
func (*Host) RemoveArchiverDropIns(context.Context, string) error          { return errNotLinux }
func (*Host) RemoveHydratorDropIns(context.Context, string) error          { return errNotLinux }
func (*Host) RemoveArchiverConfig(string) error                            { return errNotLinux }
func (*Host) RemoveHydratorConfig(string) error                            { return errNotLinux }
func (*Host) ReadArchiveSealed(string) (ArchiveSealedRecord, error) {
	return ArchiveSealedRecord{}, errNotLinux
}
func (*Host) ReadRestoreNamespaceReady(string) (RestoreNamespaceReadyRecord, error) {
	return RestoreNamespaceReadyRecord{}, errNotLinux
}
func (*Host) ReadRestoreProgress(string) (RestoreProgressRecord, error) {
	return RestoreProgressRecord{}, errNotLinux
}
func (*Host) ReadRestoreConverged(string) (RestoreConvergedRecord, error) {
	return RestoreConvergedRecord{}, errNotLinux
}
