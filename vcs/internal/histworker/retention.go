package histworker

// The retention loop: history storage is bounded by the root predicate
// (named cuts + the newest K ready cuts per branch + everything pinned);
// the only release work a loop must drive is adoption consumers, which
// otherwise accumulate one unreleased pin per adoption forever. The
// database owns the policy (pfh.retention_release); this loop only turns
// the crank, and the ordinary GC sweep collects whatever falls out of the
// root set. A database without the retention surface answers "undefined
// function", which the loop treats as "no retention work exists" so
// mixed-version deployments stay healthy.

import (
	"context"
	"errors"
)

// retentionBatch bounds one retention pass (a structural constant of the
// maintenance loop, not a tunable).
const retentionBatch = 64

func (w *Worker) retentionPass(ctx context.Context) (bool, error) {
	released, err := w.repo.RetentionRelease(ctx, retentionBatch)
	if err != nil {
		if errors.Is(err, ErrCapabilityMissing) {
			return false, nil
		}
		return false, err
	}
	if released > 0 {
		w.metrics.Counter("pfh_worker_retention_released_total").Add(released)
		w.log.Info("retention_released", map[string]any{"adoptionConsumers": released})
	}
	return released > 0, nil
}
