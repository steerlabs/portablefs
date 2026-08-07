package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
)

// EVERY STATE A MOUNT RECORD CAN REACH MUST HAVE A COMMAND THAT ENDS IT.
//
// A killed `portablefs umount` left an intent record latched at
// phase:"unmounting". That phase is not one of the resumable cleanup phases, so
// nothing reconciled it; `portablefs mount` refused every future mount at that
// path with "an incomplete prior mount operation (unmounting) remains"; and the
// only way out was for the operator to delete
// ~/.local/state/portablefs/mounts/*.json by hand. A product whose documented
// recovery is "edit our state directory" has no recovery.
//
// --discard-record is that missing terminal. It is deliberately NOT a force: it
// unmounts nothing, signals nothing, and parks nothing. It removes BOOKKEEPING,
// and only after proving that every resource the bookkeeping could still be
// speaking for is already gone:
//
//  1. No kernel mount exists at the path. Proven with getfsstat(2), which reads
//     the kernel's own mount table and therefore keeps answering while the
//     filesystem at that path is wedged.
//  2. The recorded mount owner process is gone (or was never identified).
//  3. The incomplete operation's owner process is gone — the killed umount.
//  4. portablefsd's DURABLE attach inventory does not name the path, so no
//     daemon-side attach is being orphaned.
//  5. A live portablefsd, if one is reachable, owns no attach at the path.
//
// Any one of those surviving is a refusal that names the exact command which
// owns that resource instead. The result: a record whose owners are provably
// gone is always reconcilable, and a record whose owners are NOT gone can never
// be discarded out from under them.
func (e *cmdEnv) discardMountRecord(
	o *commonOpts,
	stateDir string,
	mountPath string,
	st *mountState,
	operation *mountOperation,
	finalize func() error,
) int {
	var blockers []error

	mount, tableErr := exactKernelMountAt(mountPath)
	switch {
	case tableErr != nil:
		blockers = append(blockers, fmt.Errorf("the kernel mount table could not be read, so mount absence is unproven: %w", tableErr))
	case mount != nil:
		blockers = append(blockers, fmt.Errorf(
			"a kernel mount is still present at %s (%s from %s); run `portablefs umount %s` (add --force to abandon an unshippable tail) — --discard-record never unmounts",
			mountPath, mount.fsType, mount.source, mountPath,
		))
	}

	if st != nil && mountProcessMatches(st) {
		blockers = append(blockers, fmt.Errorf(
			"the recorded mount owner pid %d is still running; stop it with `portablefs umount %s` rather than discarding its record",
			st.PID, mountPath,
		))
	}

	if operation != nil && operation.prior != nil && mountIntentOperationOwnerMatches(operation.prior) {
		blockers = append(blockers, fmt.Errorf(
			"the incomplete %s operation is still owned by live pid %d; let it finish or stop it before discarding its record",
			operation.prior.Phase, operation.prior.OperationOwnerPID,
		))
	}

	daemonStateDir := filepath.Join(filepath.Dir(stateDir), "portablefsd")
	persisted, inventoryErr := portablefsd.ReadPersistedAttachInventory(daemonStateDir)
	if inventoryErr != nil {
		blockers = append(blockers, fmt.Errorf(
			"the durable portablefsd attach inventory could not be read, so an orphaned write-back tail cannot be ruled out: %w", inventoryErr,
		))
	}
	for _, entry := range persisted {
		if filepath.Clean(entry.MountPath) != mountPath {
			continue
		}
		// A durable attach is a claim on the path that only the exact unmount
		// may retire. --discard-record removes bookkeeping; it must never
		// orphan a daemon-side attach that still names this mount.
		blockers = append(blockers, fmt.Errorf(
			"portablefsd still holds a durable attach %s for %s; "+
				"retire it with `portablefs umount --force %s` first",
			entry.AttachRef, mountPath, mountPath,
		))
	}

	if live, liveErr := liveDaemonAttachAt(mountPath); liveErr != nil {
		blockers = append(blockers, fmt.Errorf("a live portablefsd could not be inventoried, so attach absence is unproven: %w", liveErr))
	} else if live {
		blockers = append(blockers, fmt.Errorf(
			"a live portablefsd owns an attach at %s; run `portablefs umount %s` (add --force to abandon an unshippable tail)",
			mountPath, mountPath,
		))
	}

	if len(blockers) != 0 {
		return e.fail("umount", errors.Join(append(
			[]error{fmt.Errorf("refusing to discard the record for %s: its resources are not all gone", mountPath)},
			blockers...,
		)...))
	}

	discardedPhase := ""
	if operation != nil && operation.prior != nil {
		discardedPhase = operation.prior.Phase
	}
	hadState := st != nil
	if err := removeMountState(stateDir, mountPath); err != nil {
		return e.fail("umount", fmt.Errorf("discard mount state record for %s: %w", mountPath, err))
	}
	if err := finalize(); err != nil {
		return e.fail("umount", fmt.Errorf("discard incomplete mount operation record for %s: %w", mountPath, err))
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{
			"mountPath":        mountPath,
			"unmounted":        false,
			"discardedRecord":  true,
			"discardedState":   hadState,
			"discardedIntent":  discardedPhase != "",
			"discardedPhase":   discardedPhase,
			"provenResourceOK": true,
		})
	}
	if discardedPhase != "" {
		fmt.Fprintf(e.stdout, "discarded the mount record and the incomplete %s operation for %s; nothing was mounted there and nothing was unmounted\n", discardedPhase, mountPath)
	} else {
		fmt.Fprintf(e.stdout, "discarded the mount record for %s; nothing was mounted there and nothing was unmounted\n", mountPath)
	}
	return 0
}
