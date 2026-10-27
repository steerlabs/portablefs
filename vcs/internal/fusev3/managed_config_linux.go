//go:build linux

package fusev3

import (
	"errors"

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/permissionclock"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
)

// ManagedConfig supplies real owners, including the privileged removal
// handoff. Supplying a FUSE descriptor never grants serving admission.
type ManagedConfig struct {
	Admission   *workspaceadmission.Reader
	Permit      mountenrollment.Permit
	Clock       workspaceClock
	RTC         permissionclock.UTCReader
	Renewer     *mountenrollment.Renewer
	Standalone  bool
	Persist     func(WorkspaceObservation) error
	FUSE, Abort int
	Remove      func(mode string, cause error) error
}

func (c *ManagedConfig) validate() error {
	if c.RTC == nil || c.Admission == nil || c.Clock == nil || c.Persist == nil || c.Remove == nil || c.FUSE < 3 || c.Abort < 3 || c.FUSE == c.Abort || c.Standalone == (c.Renewer != nil) {
		return errors.New("fusev3: incomplete managed ownership")
	}
	_, err := c.Admission.Recovery(c.Permit.Generation, c.Permit.GateSerial)
	return err
}

func (m *Mount) RevokeWorkspace(cause error) {
	if m.workspace != nil {
		m.revoke(cause)
	}
}
