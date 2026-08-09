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
	XFSQuotaBinary, SystemctlBinary, SystemdRunBinary, SysusersBinary      string
	Runner                                                                 CommandRunner
	Now                                                                    func() time.Time
}

type Host struct{}

func New(Config) (*Host, error) { return nil, errors.New("cellhost: supported only on Linux") }

func (*Host) Apply(_ context.Context, _ cellplan.VolumePlan, _ cellhelper.Assignment) controlplane.VolumeObservation {
	return controlplane.VolumeObservation{Error: "cellhost: supported only on Linux"}
}

func (*Host) Observe(_ context.Context, _ cellplan.VolumePlan, _ cellhelper.Assignment) controlplane.VolumeObservation {
	return controlplane.VolumeObservation{Error: "cellhost: supported only on Linux"}
}
