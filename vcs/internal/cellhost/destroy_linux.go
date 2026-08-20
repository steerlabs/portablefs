//go:build linux

package cellhost

import (
	"context"
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

// Destroy performs the five verified host operations of archive-sequence step
// 4 (docs/tiered-storage/identity-lifecycle-and-capacity.md section 2) and
// returns the destroy proof:
//
//  1. zero the XFS project quota and remove the project tree,
//  2. remove the per-volume sysusers configuration (the account is retained),
//  3. disable and remove the systemd drop-ins,
//  4. remove the volume ConfigRoot,
//  5. remove the volume StateRoot.
//
// Preconditions are proof, not assumption: the authority units must be absent
// by the same systemd + cgroup-empty test fencing uses, and the archiver and
// hydrator units must be inactive. Destroy never stops anything - a live
// authority means the manager has not finished quiescing, and the answer is to
// refuse, not to race it.
//
// Every step treats already-absent as satisfied, so a retry after a partial
// crash converges. The returned record is built by re-checking each
// postcondition after the actions, never from which actions this run
// performed, which is what makes the second run's proof identical to the
// first's. Any unsatisfied postcondition is an error naming it, and no proof
// hash is returned.
func (host *Host) Destroy(ctx context.Context, input DestroyInput) (DestroyResult, error) {
	if !cellplan.ValidID(input.VolumeID) || !cellplan.ValidID(host.cfg.CellID) ||
		!authorityNamePattern.MatchString(input.AuthorityID) ||
		!authorityNamePattern.MatchString(input.AuthorityServerName) ||
		input.AuthorityEpoch == 0 || input.PlacementSequence == 0 || input.ProjectID == 0 ||
		input.ServiceUID < 1000 || input.ServiceGID < 1000 || input.ListenPort == 0 {
		return DestroyResult{}, ErrInvalid
	}
	absent, err := host.authorityAbsent(ctx, input.VolumeID)
	if err != nil {
		return DestroyResult{}, fmt.Errorf("cellhost: destroy precondition: %w", err)
	}
	if !absent {
		return DestroyResult{}, errors.New("cellhost: destroy refuses to run without local authority-absence proof")
	}
	if err := host.archiveUnitsInactive(ctx, input.VolumeID); err != nil {
		return DestroyResult{}, err
	}

	// (1) Quota first, then the tree. Zeroing before removal means that if the
	// helper dies between the two, what is left behind is a directory with no
	// limit rather than a limit charging a project whose directory is gone.
	treeAbsentBefore := !host.volumeExists(input.VolumeID)
	quotaCleared := treeAbsentBefore
	if !treeAbsentBefore || input.QuotaWasApplied {
		if zeroErr := host.zeroProjectQuota(ctx, input.VolumeID, input.ProjectID); zeroErr != nil {
			if !treeAbsentBefore {
				return DestroyResult{}, zeroErr
			}
			// The tree is already gone. An XFS project quota record with no
			// directory charges nothing and enforces nothing, and the project
			// ID is never reused, so failing to re-zero an orphaned record
			// cannot un-destroy anything and must not block the retry.
		} else {
			quotaCleared = true
		}
	}
	if err := removeTreeBeneath(host.cfg.CellRoot, input.VolumeID); err != nil {
		return DestroyResult{}, err
	}

	// (2) The sysusers configuration goes; the account stays. Allocator
	// identities are never reused, so the account can never be handed to
	// another volume, and keeping it keeps every file that ever belonged to
	// this placement attributable in an audit or a stray backup.
	if err := removeTreeBeneath(host.cfg.SysusersRoot, sysusersConfigName(input.VolumeID)); err != nil {
		return DestroyResult{}, err
	}

	// (3) Disable, remove both drop-in directories, reload.
	if err := host.disableAuthoritySocket(ctx, input.VolumeID); err != nil {
		return DestroyResult{}, err
	}
	if err := host.removeAuthorityDropIns(ctx, input.VolumeID); err != nil {
		return DestroyResult{}, err
	}
	if err := host.RemoveArchiverDropIns(ctx, input.VolumeID); err != nil {
		return DestroyResult{}, err
	}
	if err := host.RemoveHydratorDropIns(ctx, input.VolumeID); err != nil {
		return DestroyResult{}, err
	}

	// (4) and (5). ConfigRoot and StateRoot are not required to be XFS, so the
	// remover is rooted at the pinned path and confined by openat2 the same
	// way, without the cell root's filesystem check.
	if err := removeTreeBeneath(host.cfg.ConfigRoot, input.VolumeID); err != nil {
		return DestroyResult{}, err
	}
	if err := removeTreeBeneath(host.cfg.StateRoot, input.VolumeID); err != nil {
		return DestroyResult{}, err
	}

	record := DestroyRecord{
		AuthorityEpoch:      input.AuthorityEpoch,
		AuthorityID:         input.AuthorityID,
		AuthorityServerName: input.AuthorityServerName,
		CellID:              host.cfg.CellID,
		ListenPort:          input.ListenPort,
		PlacementSequence:   input.PlacementSequence,
		ProjectID:           input.ProjectID,
		ServiceGID:          input.ServiceGID,
		ServiceUID:          input.ServiceUID,
		VolumeID:            input.VolumeID,
	}
	postconditions, err := host.verifyDestroyed(input.VolumeID, quotaCleared)
	record.Postconditions = postconditions
	if err != nil {
		return DestroyResult{Record: record}, err
	}
	if unsatisfied := postconditions.Unsatisfied(); unsatisfied != "" {
		return DestroyResult{Record: record}, fmt.Errorf("cellhost: destroy postcondition %s is unsatisfied for volume %s", unsatisfied, input.VolumeID)
	}
	proof, err := record.ProofSHA256()
	if err != nil {
		return DestroyResult{Record: record}, err
	}
	return DestroyResult{Record: record, ProofSHA256: proof}, nil
}

// verifyDestroyed re-derives every postcondition from the filesystem. Five of
// the six are fresh lstats through O_NOFOLLOW descriptors on the pinned roots.
//
// quota_cleared is the exception and the only one carried from the action
// phase, because a cleared project quota leaves nothing on disk to look at:
// once the project directory is gone there is no inode to read a project ID
// from, and reading the quota table back would need quotactl(2) - privilege
// this helper deliberately does not take for a question whose answer cannot
// matter. It is therefore defined as the contract defines it: the zeroing
// succeeded this run, or the project directory was already absent. Both cases
// mean the same thing, since a project quota record without a directory
// enforces nothing and the project ID is never reused.
func (host *Host) verifyDestroyed(volumeID string, quotaCleared bool) (DestroyPostconditions, error) {
	tree, err := absentBeneath(host.cfg.CellRoot, volumeID)
	if err != nil {
		return DestroyPostconditions{}, err
	}
	sysusers, err := absentBeneath(host.cfg.SysusersRoot, sysusersConfigName(volumeID))
	if err != nil {
		return DestroyPostconditions{}, err
	}
	serviceDropIn, err := absentBeneath(host.cfg.SystemdUnitRoot, authorityServiceDropInDirectory(volumeID))
	if err != nil {
		return DestroyPostconditions{}, err
	}
	socketDropIn, err := absentBeneath(host.cfg.SystemdUnitRoot, authoritySocketDropInDirectory(volumeID))
	if err != nil {
		return DestroyPostconditions{}, err
	}
	archiverDropIn, err := absentBeneath(host.cfg.SystemdUnitRoot, archiverUnit(volumeID)+".d")
	if err != nil {
		return DestroyPostconditions{}, err
	}
	hydratorDropIn, err := absentBeneath(host.cfg.SystemdUnitRoot, hydratorUnit(volumeID)+".d")
	if err != nil {
		return DestroyPostconditions{}, err
	}
	configRoot, err := absentBeneath(host.cfg.ConfigRoot, volumeID)
	if err != nil {
		return DestroyPostconditions{}, err
	}
	stateRoot, err := absentBeneath(host.cfg.StateRoot, volumeID)
	if err != nil {
		return DestroyPostconditions{}, err
	}
	return DestroyPostconditions{
		ConfigRootAbsent:   configRoot,
		DropInsAbsent:      serviceDropIn && socketDropIn && archiverDropIn && hydratorDropIn,
		QuotaCleared:       quotaCleared,
		StateRootAbsent:    stateRoot,
		SysusersConfAbsent: sysusers,
		TreeAbsent:         tree,
	}, nil
}

// zeroProjectQuota releases the project's hard limits before the tree goes.
//
// CRITICAL, and the same rule as the provisioning quota units: this transient
// must not set PrivateDevices or PrivateTmp. Either property puts the unit in
// its own mount namespace, where xfs_quota would operate on a different view
// of the cell mount than the one whose quota state must change. The capability
// set is the same closed set provisioning uses, and the command shape is
// fixed: only the project ID varies, and it is an integer from the signed
// assignment.
func (host *Host) zeroProjectQuota(ctx context.Context, volumeID string, projectID uint32) error {
	arguments := transientArguments(
		"portablefs-xfs-destroy-"+volumeID, host.cfg.XFSQuotaBinary,
		[]string{"-x", "-c", fmt.Sprintf("limit -p bhard=0 ihard=0 %d", projectID), host.cfg.CellRoot},
		"CAP_DAC_OVERRIDE CAP_FOWNER CAP_SYS_ADMIN", false,
	)
	if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemdRunBinary, arguments...); err != nil {
		return commandError("zero XFS project quota", output, err)
	}
	return nil
}

func sysusersConfigName(volumeID string) string { return "portablefs-volume-" + volumeID + ".conf" }
