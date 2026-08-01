package writeback

// Metadata-lane admission.
//
// The data plane has had a pre-lock admission gate since the credit controller
// landed: a bulk write resolves its lane and collects its credit BEFORE the
// frontend takes a namespace or handle lock, so a saturated lane paces the
// writer instead of failing it, and the wait is taken holding nothing.
//
// The namespace lane had no such gate. A delegated mkdir/create/rename/unlink/
// truncate/xattr reserved against the metadata lane under e.mu, and a
// reservation that did not fit RIGHT NOW — while being provably able to fit an
// empty lane — was answered ErrUplinkStalled on the spot. That is an EIO an
// application cannot act on: the store is not full, the far end is not dead,
// and the very same operation is admissible one authority advance later. A
// healthy advancing stream that fills the metadata reserve therefore aborted
// `mkdir(2)` instantly, and the only recovery available to the application was
// a retry — the prohibited workaround.
//
// This file is the namespace lane's half of the same contract the data lane
// already keeps:
//
//   - The WAIT is pre-lock and bounded. AdmitMetadataMutation is called by the
//     frontend classifier BEFORE any namespace lock, exactly where
//     AcquireDataCredit is called, and it blocks on the ONE event that frees
//     metadata bytes — the authority applying the backlog — never on a lock.
//   - ErrUplinkStalled comes from the watchdog and nowhere else. The gate never
//     synthesizes a stall verdict from elapsed time: when its budget expires it
//     ASKS (Engine.StallVerdict) rather than inferring, because elapsed time
//     proves nothing here — the watchdog's window runs from the last watermark
//     advance, not from the moment this mutation began to wait.
//   - ENOSPC stays definite. An operation larger than the lane at any occupancy
//     can never fit and is refused immediately, at every occupancy, exactly as
//     the data lane refuses an oversized write.
//   - Under the locks the engine only CHECKS. A reservation that still does not
//     fit when the mutation reaches e.mu is answered errMetadataHeadroom, which
//     is an ErrLaneChanged: the operation unwinds with every frontend lock
//     released and re-enters admission out here, where waiting is free. It is
//     never a wait taken under e.mu with a delegation held — that is the
//     namespace lane's drain dependency the whole design exists to bound
//     (docs/liveness-followups.md §1).
//
// Sizing. The metadata reserve (metadataReserveBytes, 64 MiB of the hard cap)
// is untouchable by bulk data, and one namespace mutation is a few hundred
// bytes, so reaching the admission gate at all means the NAMESPACE stream alone
// outran the uplink by ~10^5 operations. The gate is therefore rare by
// construction and costs two atomic-ish reads on the hot path; metadata stays
// latency-critical.

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// errMetadataHeadroom is the namespace lane's exact analogue of
// errDataHeadroom: the metadata reservation could not fit right now, but the
// operation is not oversized — it would fit an empty lane.
//
// It is an ErrLaneChanged, and that is the whole point. The mutation is inside
// e.mu (and, above it, the frontend's namespace locks) when the reservation is
// refused, which is precisely where a wait is forbidden. So the engine says
// "not here" and the frontend unwinds to the pre-lock admission point and waits
// there, holding nothing. No error ever reaches the application from this path.
var errMetadataHeadroom = fmt.Errorf(
	"writeback: metadata lane has no headroom yet: %w", ErrLaneChanged,
)

// metadataAdmissionBudget bounds the TOTAL time one namespace mutation spends
// in pre-lock metadata admission. It bounds the WAIT. It does not classify the
// OUTCOME, and keeping those two jobs apart is this gate's whole contract with
// the watchdog.
//
// It used to claim both. The comment here restated clientcore's chain —
//
//	noProgressWindow (30s) + creditWaitCap (5s) = 35s  <  40s
//
// — and read it as "a genuinely stalled uplink is DECLARED stalled strictly
// before this budget can expire", which made expiry mean "the uplink is healthy
// and the namespace stream simply outran it". The arithmetic is right and the
// conclusion does not follow. The watchdog's window is measured from the last
// WATERMARK ADVANCE (flusher.advance resets lastProgress), not from the moment
// this mutation started waiting: a mutation that parks at t0 and sees the
// authority advance at t39 reaches this budget at t40 with the watchdog unable
// to declare anything before ~t69. Expiry proves neither a stall nor progress.
//
// So the budget keeps the job it can do — the pre-lock wait is bounded, and both
// it and the reply it produces land inside every enclosing bound — and the
// CLASSIFICATION at expiry is asked of the one thing that can answer it,
// Engine.StallVerdict (see metadataAdmissionExpired). Unlike the data lane there
// is still no second lane to divert to: a namespace mutation that cannot reach
// the WAL takes the authority lane by falling through, which the caller decides,
// not this gate. Expiry is therefore a definite outcome either way — the
// EIO-class stall the watchdog actually holds, or the deadline the caller's own
// operation bound already promised.
//
// A var so failure-shape tests can compress it; production never changes it.
var metadataAdmissionBudget = 40 * time.Second

// metadataAdmissionCost is the headroom one namespace mutation must find
// before it is admitted: one maximum-size WAL frame.
//
// It is deliberately the WORST case rather than the operation's own size. The
// records are not encoded yet at admission time (they are built under the
// engine's lock, from state the frontend has not yet read), so the gate cannot
// know the exact cost — and a gate that admitted on an underestimate would just
// move the refusal under the locks, which is the failure this file removes.
// Against a 64 MiB reserve one maximum frame is under 2%, so demanding it costs
// nothing in practice and makes the admitted operation's later reservation a
// near-certainty rather than a hope.
const metadataAdmissionCost = frameHeaderSize + maxMutationPayload + frameAlign

// metadataAdmissionCostFor scales that demand for caps too small to give a
// whole frame away (package fixtures, tiny caches), exactly as
// metadataReserveFor scales the lane split: it degrades to an eighth of the
// cap, which keeps the gate's shape at any size instead of turning every
// mutation on a small cap into backpressure.
func metadataAdmissionCostFor(budget int64) int64 {
	if eighth := budget / 8; eighth < metadataAdmissionCost {
		return eighth
	}
	return metadataAdmissionCost
}

// AdmitMetadataMutation is the namespace lane's pre-lock admission gate.
//
// Callers MUST invoke it BEFORE taking any namespace, inode or handle lock, and
// it takes none of the engine's own locks while it waits. A caller parked
// inside it holds nothing at all: a recall, a freeze, a close, a checkpoint and
// every data mutation run to completion with a namespace mutation queued here.
//
// Outcomes, all definite:
//
//   - nil: the metadata lane has headroom for one maximum-size frame. The
//     mutation proceeds and reserves exactly its own size under e.mu.
//   - ErrUplinkStalled: the flusher's watchdog declared the far end dead —
//     either while the gate was waiting, or when the gate reached its budget and
//     ASKED (Engine.StallVerdict). EIO-class, relayed, never synthesized here.
//   - a context error: the caller's own deadline or cancellation, or the
//     metadata admission budget expiring with the watchdog reporting a live
//     uplink.
//
// It NEVER produces ENOSPC. ENOSPC is a definite claim about a specific
// operation — "this can never fit, at any occupancy" — and the gate does not
// know the operation's size: the records are encoded later, under e.mu. The one
// place that question can be answered exactly is where the exact payloads exist
// (appendLaneLocked's maxAppendCost), and that is where it stays. A gate that
// synthesized ENOSPC from its own worst-case demand would tell an application
// to delete files because a hypothetical maximum frame would not fit.
func (e *Engine) AdmitMetadataMutation(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.MutationError(); err != nil {
		return err
	}
	admitCtx, cancel := context.WithTimeout(ctx, metadataAdmissionBudget)
	defer cancel()
	for {
		if !e.metadataLaneFull() {
			return nil
		}
		// The lane is merely occupied. One relief pass folds what the
		// authority has applied and reclaims the segments that frees, which is
		// the only thing besides an advance that can move this bound.
		e.mu.Lock()
		e.relieveBudgetLocked()
		e.mu.Unlock()
		if err := e.MutationError(); err != nil {
			return err
		}
		if !e.metadataLaneFull() {
			return nil
		}
		// Wait for the ONE event that frees metadata bytes. waitForApplied
		// returns ErrUplinkStalled only on the watchdog's verdict, and nil (to
		// re-evaluate) on an advance, its own cap, or a healthy quiet link.
		if err := e.credits.waitForApplied(admitCtx); err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				// The budget expired while the caller's own deadline still has
				// room. Ask the watchdog what that means; do not assume.
				return e.metadataAdmissionExpired(context.DeadlineExceeded)
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := admitCtx.Err(); err != nil {
			return e.metadataAdmissionExpired(err)
		}
	}
}

// metadataAdmissionExpired turns budget expiry into the outcome the LIVE
// watchdog verdict justifies.
//
// It is the only place this file names an expiry outcome, so the stalled-vs-slow
// split cannot drift between the two points the admission loop can reach it
// from — and it is asked, never derived. cause is the expiry the loop observed;
// it survives in the healthy answer so the caller still sees the deadline class
// its own bound promised.
func (e *Engine) metadataAdmissionExpired(cause error) error {
	verdict := e.StallVerdict()
	if verdict.Stalled {
		// Unreachable before this arm consulted the verdict: it assumed its own
		// arithmetic had already proved the uplink healthy, so a mutation that
		// waited out a genuinely dead far end was answered an interrupted
		// operation instead of the EIO-class truth.
		return fmt.Errorf(
			"writeback: metadata admission budget expired and the watchdog holds "+
				"a stall verdict: %w", ErrUplinkStalled,
		)
	}
	return fmt.Errorf(
		"writeback: metadata admission budget expired; the watchdog reports a "+
			"live uplink (%s before it could declare a stall), so this is the "+
			"budget's own deadline and not a stall: %w",
		verdict.Remaining, cause,
	)
}

// metadataLaneFull answers the gate's question without charging anything and
// without taking e.mu: whether the metadata lane has room for one more
// namespace mutation right now.
//
// The authoritative decision is still the exact reservation taken under the WAL
// mutex at append time (appendLaneLocked). This is the pre-lock question, and
// being answered from a slightly stale footprint is exactly right: an admitted
// mutation whose reservation nonetheless fails unwinds through
// errMetadataHeadroom and comes back here, so the gate never has to be more
// precise than the reservation it precedes.
func (e *Engine) metadataLaneFull() bool {
	w := e.wal
	if w == nil {
		// No stream yet: the first mutation creates it, and an empty stream has
		// the whole cap.
		return false
	}
	budget := e.cfg.BudgetBytes
	if budget <= 0 {
		return false
	}
	// maxAppendCost is the cost the lane holds back at EVERY occupancy: one
	// segment rollover, the live-delegation re-emit set, and the control
	// reserve. The gate's own demand rides on top of it.
	fixed, err := w.maxAppendCost(nil)
	if err != nil {
		// The WAL cannot cost the append; the reservation under e.mu owns that
		// failure, and it is not an admission question.
		return false
	}
	cost := fixed + metadataAdmissionCostFor(budget)
	if cost > budget {
		// The gate's worst-case demand does not fit this cap at any occupancy.
		// That is a statement about the DEMAND, not about the operation, so it
		// must not become backpressure — let the exact reservation decide.
		return false
	}
	return w.DiskBytes()+cost > budget
}

// MetadataLaneFull reports whether the namespace lane would make a mutation
// wait right now. It charges nothing and is exported for Status/observability
// and for frontends that want to surface backpressure without taking it.
func (e *Engine) MetadataLaneFull() bool {
	return e != nil && e.metadataLaneFull()
}

// MetadataAdmissionBudget publishes the bound the namespace lane's pre-lock
// wait is proved against, so that proof is a test rather than a comment.
func MetadataAdmissionBudget() time.Duration { return metadataAdmissionBudget }
