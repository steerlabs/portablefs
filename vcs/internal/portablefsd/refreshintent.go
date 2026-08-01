package portablefsd

// THE PER-ITEM REFRESH INTENT.
//
// ── WHAT REFUSING COST ──────────────────────────────────────────────────────
//
// The size-mutation reservation (refreshpin.go) is taken at pre-lock admission
// and released only once the handler has published, because that is exactly the
// interval in which the mutation can commit. It therefore spans the frontend
// mirrors, the namespace and handle locks, and the handler's whole authority
// round trip — and an entirely ORDINARY request can sit in that span for a
// second or more merely by queueing behind an exclusive rename or reclaim, or
// by waiting on one healthy-but-slow authority operation.
//
// The refresh's answer to a reservation used to be to REFUSE and retry:
// staleSampleRetries+1 attempts, refreshCoalesce apart, ≈1.025s of budget. That
// made contention indistinguishable from non-convergence:
//
//   - ONE ordinary mutation outliving the budget exhausted the exact
//     transaction, and its caller — the authority event watcher — turns a failed
//     exact refresh into failCoherence, which is TERMINAL and remount-only. A
//     mount could be frozen by nothing but a slow write.
//   - OVERLAPPING writers reached the same end with no slow mutation at all.
//     Arrivals had no reason to yield: a refresh that only ever RE-CHECKS what
//     is reserved at each tick has no claim of its own, so a stream of ordinary
//     writers keeps the item covered and starves it indefinitely.
//
// Raising the retry count answers neither. The first shape only needs a slower
// mutation, and the second has no bound at all — it is starvation, not a
// too-short budget.
//
// ── WHAT THE INTENT IS ──────────────────────────────────────────────────────
//
// So a refresh declares an INTENT on the item before it begins, and the intent
// is a fair queue rather than a check:
//
//   - Reservations OUTSTANDING when the intent registers are untouched. They
//     drain on their own terms, which is the only correct thing to do with a
//     mutation that is already on its way to a commit.
//   - Reservations arriving AFTER it QUEUE, on the same channel discipline the
//     pin uses, so the drain can actually complete. This is the priority the
//     refresh previously lacked.
//   - When the last outstanding reservation is released the intent is DRAINED,
//     and the refresh proceeds to sample, arm, and pin. Because the intent is
//     still held, the pin arms over an item on which no reservation can have
//     appeared: the intent becomes the pin without ever reopening the door.
//
// Contention is then a WAIT under the refresh transaction's own bounded
// context, not a consumed retry, and failCoherence is left for the thing it
// should always have meant: genuine no-progress.
//
// ── WHY THE DRAIN CANNOT DEADLOCK AGAINST A RESERVATION HOLDER ──────────────
//
// Two properties, and both are the same discipline the pin already obeys:
//
//  1. The drain is BOUNDED BY THE HOLDER'S OWN OPERATION DEADLINE. Every
//     reservation is taken inside a request that carries exactly one absolute
//     deadline (clientcore.WithOperationDeadline), and the reservation is
//     released when that request's handler finishes, whatever it finishes as.
//     refreshIntentDrainBudget is that bound plus slack, so a drain that does
//     not complete is a holder that has outlived its own deadline — genuine
//     no-progress, and correctly reported as such.
//
//  2. A QUEUED RESERVATION HOLDS NOTHING. It waits at attach.admitRequest, the
//     one pre-lock admission point, before any frontend lock — the same place
//     and for the same reason the pin's waiters wait there (refreshpin.go). So
//     a queued mutation can never be part of a cycle: it owns no lock the drain
//     could be waiting on.
//
// And the refresh itself holds nothing while it waits: it has not sampled, not
// opened the file, and not issued the ftruncate whose upcall it would then need
// the daemon to service. The one call that could close a cycle — a refresh
// waiting for a drain that includes ITS OWN reservation — cannot arise, because
// every caller of the exact refresh releases its size token before asking for
// the refresh it owes (control.go), and the remaining callers (the authority
// invalidation watcher and the publication-fence backstop) hold none at all.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
)

// refreshIntentDrainBudget bounds the wait for reservations outstanding when an
// intent registers. It is one frontend operation's absolute deadline plus slack,
// because that is what actually bounds a reservation: it is released when its
// request's handler finishes, and that handler cannot outlive its own deadline.
//
// A var so contention tests can compress it; production never changes it.
var refreshIntentDrainBudget = clientcore.OperationAdmissionBudget() + 5*time.Second

// refreshIntent is one pending refresh's claim on an item, held from before the
// pass samples until the pass is over.
//
// Both channels are closed — never sent on — so any number of waiters observe
// the transition without the closer knowing how many there are.
type refreshIntent struct {
	// done is closed when the intent is released. Mutations queued behind it
	// wake and reserve.
	done chan struct{}
	// drained is closed once no reservation is outstanding for the item, which
	// (because the intent is already blocking new ones) is the moment the
	// refresh may proceed.
	drained     chan struct{}
	drainClosed bool
	release     sync.Once
}

// refreshIntentBlockerLocked returns the channel a size mutation on itemID must
// wait for before it may reserve, or nil if it may reserve now. Callers hold
// a.mu.
//
// The pin is tested first because it is the stronger statement — a syscall is in
// flight — but during a pass's own transaction both are held by the same pass,
// so which one a mutation waits on is immaterial: it wakes when the pass is
// finished with the item either way.
func (a *attach) refreshIntentBlockerLocked(itemID uint64) chan struct{} {
	if pin := a.refreshPins[itemID]; pin != nil {
		return pin.done
	}
	if intent := a.refreshIntents[itemID]; intent != nil {
		return intent.done
	}
	return nil
}

// signalRefreshIntentDrainLocked publishes the drain when the item's last
// outstanding reservation has been released. Callers hold a.mu.
func (a *attach) signalRefreshIntentDrainLocked(itemID uint64) {
	intent := a.refreshIntents[itemID]
	if intent == nil || intent.drainClosed {
		return
	}
	if a.sizeMutationReservations[itemID] > 0 {
		return
	}
	intent.drainClosed = true
	close(intent.drained)
}

// acquireRefreshIntent registers this pass's intent on itemID and returns once
// every reservation that was outstanding at registration has drained.
//
// It holds no lock while it waits, and the wait is bounded twice over: by the
// caller's own context — the refresh transaction's — and by
// refreshIntentDrainBudget. Its error is therefore a statement about genuine
// no-progress, which is the only thing its callers are entitled to escalate.
//
// A zero itemID is an item the registry cannot name; no mutation can reserve it
// and the intent is inert.
func (a *attach) acquireRefreshIntent(ctx context.Context, itemID uint64) (func(), error) {
	if itemID == 0 {
		return func() {}, nil
	}
	for {
		a.mu.Lock()
		if a.refreshIntents == nil {
			a.refreshIntents = map[uint64]*refreshIntent{}
		}
		if held := a.refreshIntents[itemID]; held != nil {
			// Another pass is already pending on this item. Passes are
			// serialized by the per-item refresh gate, so this is a narrow
			// overlap rather than a queue; wait it out rather than arming a
			// second intent whose drain the first one's pin would satisfy.
			done := held.done
			a.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf(
					"portablefsd: refresh intent for item %d: %w", itemID, ctx.Err(),
				)
			}
		}
		intent := &refreshIntent{
			done:    make(chan struct{}),
			drained: make(chan struct{}),
		}
		a.refreshIntents[itemID] = intent
		// From this instant every ARRIVING size mutation on the item queues.
		// Whatever was already outstanding drains on its own terms.
		a.signalRefreshIntentDrainLocked(itemID)
		a.mu.Unlock()

		release := func() {
			intent.release.Do(func() {
				a.mu.Lock()
				if a.refreshIntents[itemID] == intent {
					delete(a.refreshIntents, itemID)
				}
				a.mu.Unlock()
				close(intent.done)
			})
		}
		drainCtx, cancelDrain := context.WithTimeout(ctx, refreshIntentDrainBudget)
		select {
		case <-intent.drained:
			cancelDrain()
			return release, nil
		case <-drainCtx.Done():
			cancelDrain()
			// The intent is given back before reporting: a pending intent left
			// behind a pass that is not running would queue every size mutation
			// on the item for nothing.
			release()
			return nil, fmt.Errorf(
				"portablefsd: refresh intent for item %d: size mutations did not "+
					"drain within %s: %w", itemID, refreshIntentDrainBudget, drainCtx.Err(),
			)
		}
	}
}
