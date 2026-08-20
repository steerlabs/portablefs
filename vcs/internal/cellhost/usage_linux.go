//go:build linux

package cellhost

import (
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"golang.org/x/sys/unix"
)

// MeasureUsage reports the placement's measured usage, the input to the
// capacity model in docs/tiered-storage/identity-lifecycle-and-capacity.md
// section 5.
//
// The mechanism is statfs(2) on the volume's project directory, nothing more.
// For a directory carrying a project ID and XFS_DIFLAG_PROJINHERIT on a mount
// with -o prjquota and a hard limit set, xfs_fs_statfs answers through
// xfs_qm_statvfs and rewrites f_blocks/f_bfree and f_files/f_ffree to that
// project's limits and usage - the same mechanism, verified on Linux 6.8, that
// the authority's own Volume.StatFS documents and relies on
// (vcs/internal/xfsstore/metadata_linux.go:212-250). It needs no capability:
// quotactl(2) is privileged, statfs(2) on a directory is not. This adds no
// privileged surface to the helper, and it reuses the descriptor discipline
// the provision-verify path already uses.
//
// The reading is only project-scoped because provisioning set a limit; XFS
// reports cell-wide values for a project with no limit. verifyProvisionedVolume
// is what proves the limit is installed, and it runs on the same descriptor.
//
// An absent project directory returns ErrVolumeAbsent so the caller can tell an
// already-destroyed or not-yet-provisioned placement from a broken host.
func (host *Host) MeasureUsage(volumeID string) (uint64, uint64, error) {
	if !cellplan.ValidID(volumeID) {
		return 0, 0, ErrInvalid
	}
	volumeFD, err := host.openVolumeDirectory(volumeID, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return 0, 0, fmt.Errorf("%w: %s", ErrVolumeAbsent, volumeID)
		}
		return 0, 0, fmt.Errorf("cellhost: open volume project directory: %w", err)
	}
	defer unix.Close(volumeFD)
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(volumeFD, &filesystem); err != nil {
		return 0, 0, fmt.Errorf("cellhost: measure volume usage: %w", err)
	}
	// Fail closed on any statfs result that cannot describe a project: a
	// nonsensical reading must never be reported as low usage, which is what
	// admission would act on.
	if filesystem.Bsize <= 0 || filesystem.Bfree > filesystem.Blocks || filesystem.Ffree > filesystem.Files {
		return 0, 0, errors.New("cellhost: invalid XFS project statfs result")
	}
	usedBlocks := filesystem.Blocks - filesystem.Bfree
	if usedBlocks > ^uint64(0)/uint64(filesystem.Bsize) {
		return 0, 0, errors.New("cellhost: invalid XFS project statfs block result")
	}
	return usedBlocks * uint64(filesystem.Bsize), filesystem.Files - filesystem.Ffree, nil
}
