//go:build linux

package cellhost

import (
	"context"
	"fmt"
)

// The per-volume unit names the helper owns. Every one is derived from a
// validated volume UUID under a fixed template name; nothing here is ever
// taken from a plan payload.
func authorityServiceUnit(volumeID string) string {
	return "portablefs-authority@" + volumeID + ".service"
}
func authoritySocketUnit(volumeID string) string {
	return "portablefs-authority@" + volumeID + ".socket"
}
func archiverUnit(volumeID string) string { return "portablefs-archiver@" + volumeID + ".service" }
func hydratorUnit(volumeID string) string { return "portablefs-hydrator@" + volumeID + ".service" }

func authorityServiceDropInDirectory(volumeID string) string {
	return authorityServiceUnit(volumeID) + ".d"
}

func authoritySocketDropInDirectory(volumeID string) string {
	return authoritySocketUnit(volumeID) + ".d"
}

// archiveUnitsInactive proves no archiver or hydrator is running for the
// volume. Those processes hold the volume tree open and speak to the archive
// store; removing the tree under a live one would race an in-flight export or
// namespace restore against destruction.
//
// The check is deliberately asymmetric, because `systemctl is-active` is:
// exit 0 means the unit is running, and every non-zero exit - inactive,
// failed, or unknown-unit for a template that was never installed on this cell
// - means it is not. Only a zero exit refuses; nothing is inferred from the
// text of the failure.
func (host *Host) archiveUnitsInactive(ctx context.Context, volumeID string) error {
	checks := []struct {
		unit string
		kind string
	}{{archiverUnit(volumeID), "archiver"}, {hydratorUnit(volumeID), "hydrator"}}
	for _, check := range checks {
		absent, err := host.workerAbsent(ctx, check.unit, check.kind)
		if err != nil || !absent {
			if err != nil {
				return err
			}
			return fmt.Errorf("cellhost: %s is still active; destroy refuses to remove a volume under a live archiver or hydrator", check.unit)
		}
	}
	return nil
}

// disableAuthoritySocket removes the socket's enablement symlinks. A unit that
// is not enabled, or whose unit file is already gone, cannot be disabled and
// is already in the desired state; that case is distinguished by asking
// `is-enabled` rather than by matching systemctl's error text. Anything else
// is a real failure: an enabled socket would re-activate the authority for a
// volume whose data is being removed.
func (host *Host) disableAuthoritySocket(ctx context.Context, volumeID string) error {
	socket := authoritySocketUnit(volumeID)
	output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "disable", socket)
	if err == nil {
		return nil
	}
	if _, enabledErr := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "is-enabled", socket); enabledErr != nil {
		return nil
	}
	return commandError("disable authority socket", output, err)
}

// removeAuthorityDropIns removes both per-volume drop-in directories and makes
// systemd forget them. The daemon-reload is part of the operation, not a
// courtesy: until it runs, systemd still holds the removed User=, BindPaths=,
// and ListenStream= of a placement whose identity tuple must never be used
// again.
func (host *Host) removeAuthorityDropIns(ctx context.Context, volumeID string) error {
	for _, directory := range []string{authorityServiceDropInDirectory(volumeID), authoritySocketDropInDirectory(volumeID)} {
		if err := removeTreeBeneath(host.cfg.SystemdUnitRoot, directory); err != nil {
			return err
		}
	}
	if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "daemon-reload"); err != nil {
		return commandError("reload systemd after removing drop-ins", output, err)
	}
	return nil
}
