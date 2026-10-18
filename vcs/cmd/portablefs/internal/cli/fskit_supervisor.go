package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
)

type fsKitMountWatcher interface {
	events() <-chan error
	close() error
}

// Registration precedes the first snapshot. Events are coalescible wakeups;
// only exact kernel inventory establishes absence. No daemon health observation
// or elapsed-time event is an input to this loop.
func superviseFSKit(st *mountState, signals <-chan os.Signal, watch func() (fsKitMountWatcher, error), present func(*mountState) (bool, error), unmount, finalize func() error, diagnostics io.Writer) (result error) {
	watcher, err := watch()
	if err != nil {
		return fmt.Errorf("establish kernel mount supervision; state and intent were preserved: %w", err)
	}
	defer func() {
		if err := watcher.close(); err != nil {
			result = errors.Join(result, fmt.Errorf("close kernel mount notification; state and intent were preserved: %w", err))
		}
	}()
	inspect := func() (bool, error) {
		mounted, err := present(st)
		if err != nil {
			return false, fmt.Errorf("kernel mount presence is unverified: %w; state and intent were preserved", err)
		}
		return mounted, nil
	}
	mounted, err := inspect()
	if err != nil {
		return err
	}
	for {
		if !mounted {
			_, err := unmountFSKitWithKernelOutcome(st, finalize)
			return err
		}
		select {
		case _, ok := <-signals:
			if !ok {
				return fmt.Errorf("supervisor signal channel ended; state and intent were preserved")
			}
			absent, err := unmountFSKitWithKernelOutcome(st, unmount)
			if err == nil {
				return nil
			}
			if absent {
				return err
			}
			// Busy/incomplete unmount makes one attempt for this signal. A later
			// explicit signal may try again; notifications only re-read inventory.
			fmt.Fprintf(diagnostics, "portablefs mount: %v\n", err)
		case err, ok := <-watcher.events():
			if !ok {
				return fmt.Errorf("kernel mount notification ended; state and intent were preserved")
			}
			if err != nil {
				return fmt.Errorf("kernel mount notification failed; state and intent were preserved: %w", err)
			}
		}
		mounted, err = inspect()
		if err != nil {
			return err
		}
	}
}

func finalizeExternallyAbsentFSKit(ctl *fsdControl, st *mountState) error {
	err := ctl.unmountRecordedAttach(st)
	if err == nil {
		return nil
	}
	// A concurrent CLI unmount can remove the registry before this request.
	// Its 404 is insufficient: require complete authenticated exact inventory.
	var status *fsdStatusError
	if !errors.As(err, &status) || status.status != 404 {
		return err
	}
	present, inventoryErr := verifyRecordedFskitAttach(ctl, st)
	if inventoryErr != nil {
		return errors.Join(err, inventoryErr)
	}
	if present {
		return err
	}
	return nil
}
