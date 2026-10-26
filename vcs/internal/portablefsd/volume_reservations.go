package portablefsd

import (
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
)

// The caller holds the daemon singleton and has decoded its complete durable
// registry. A reservation published before that registry (or left after its
// removal) is releasable only after the existing all-source/target kernel
// absence observer proves the exact planned attachment absent. Workspace
// reservations belong to another service and are never collected here.
func (r *registry) reconcileVolumeReservations(absent func(path, ref string) error) error {
	if r.loadErr != nil {
		return r.loadErr
	}
	transition, err := mountlifecycle.BeginTransition(r.reservationStateDir)
	if err != nil {
		return err
	}
	defer transition.Close()
	for _, a := range r.list() {
		reservation, err := reservationForAttach(a)
		if err != nil {
			return err
		}
		if err = transition.Reserve(reservation); err != nil {
			return err
		}
	}
	for _, reservation := range transition.Inventory() {
		if reservation.Frontend != "fskit" || r.get(reservation.Owner) != nil {
			continue
		}
		if reservation.Target == "" || absent == nil {
			return fmt.Errorf("orphan FSKit reservation has no exact absence witness")
		}
		if err = absent(reservation.Target, reservation.Owner); err != nil {
			return fmt.Errorf("reconcile orphan FSKit reservation: %w", err)
		}
		if err = transition.Release(reservation); err != nil {
			return err
		}
	}
	return nil
}
