package histworker

import (
	"context"
	"errors"
	"fmt"

	"github.com/trendup-ai/portablefs/vcs/internal/histstore"
)

// gcPass claims ONE sweepable object (worker + epoch + DB-time lease),
// deletes each claimed exact copy in its own failure domain, PROVES absence
// per copy with an independent head, and only then completes — the database
// re-fences on incarnation, reclaim generation, claim epoch, and a
// late-arriving root, resurrecting instead of finalizing. A storage failure
// releases the claim explicitly; shutdown releases NOTHING (the DB-time
// lease reclaims after expiry). Returns whether a claim was processed.
func (w *Worker) gcPass(ctx context.Context) (bool, error) {
	claim, err := w.repo.ClaimSweep(ctx, w.cfg.WorkerID,
		w.cfg.SweepMinAge.Milliseconds(), w.cfg.LeaseTTL.Milliseconds())
	if err != nil {
		return false, err
	}
	if claim == nil {
		return false, nil
	}

	// Every claimed copy must be deletable AND provably absent by THIS
	// worker; an unconfigured domain means this deployment cannot attest,
	// so the claim is released for a correctly configured sweeper.
	for _, c := range claim.Copies {
		if _, ok := w.stores.Get(c.FailureDomain); !ok {
			w.log.Error("gc_domain_unconfigured", fmt.Errorf("failure domain %q has no store", c.FailureDomain),
				map[string]any{"digest": claim.Digest})
			return true, w.releaseSweep(ctx, claim, "storage_failed")
		}
	}

	absences := make([]AbsenceReceipt, 0, len(claim.Copies))
	for _, c := range claim.Copies {
		if ctx.Err() != nil {
			// Shutdown mid-sweep: stop without asserting anything locally;
			// the lease expires and another sweeper reclaims.
			return true, ctx.Err()
		}
		store, _ := w.stores.Get(c.FailureDomain)
		if err := store.Delete(ctx, c.StorageKey); err != nil {
			w.log.Error("gc_delete_failed", err, map[string]any{
				"digest": claim.Digest, "failureDomain": c.FailureDomain,
			})
			return true, w.releaseSweep(ctx, claim, "storage_failed")
		}
		// Independent absence proof over the exact key.
		if _, err := store.Head(ctx, c.StorageKey); !errors.Is(err, histstore.ErrNotFound) {
			if err == nil {
				err = errors.New("object still present after delete")
			}
			w.log.Error("gc_absence_unproven", err, map[string]any{
				"digest": claim.Digest, "failureDomain": c.FailureDomain,
			})
			return true, w.releaseSweep(ctx, claim, "storage_failed")
		}
		absences = append(absences, AbsenceReceipt{
			FailureDomain: c.FailureDomain, StorageKey: c.StorageKey, ConfirmedAbsent: true,
		})
	}

	outcome, err := w.repo.CompleteSweep(ctx, w.cfg.WorkerID, claim, absences)
	if err != nil {
		return true, err
	}
	switch outcome {
	case "swept":
		w.metrics.Counter("pfh_worker_sweeps_total").Inc()
		w.log.Info("swept", map[string]any{
			"digest": claim.Digest, "incarnation": claim.Incarnation,
			"copies": len(absences),
		})
	default:
		w.metrics.Counter("pfh_worker_sweep_resurrected_total").Inc()
		w.log.Info("sweep_resurrected", map[string]any{
			"digest": claim.Digest, "incarnation": claim.Incarnation,
		})
	}
	return true, nil
}

func (w *Worker) releaseSweep(ctx context.Context, claim *SweepClaim, reason string) error {
	if ctx.Err() != nil {
		// Shutdown: no local-assertion release; the DB-time lease reclaims.
		return ctx.Err()
	}
	w.metrics.Counter("pfh_worker_sweep_released_total").Inc()
	return w.repo.ReleaseSweep(ctx, w.cfg.WorkerID, claim, reason)
}
