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
//   - Reservations arriving AFTER it QUEUE, so the drain can actually complete.
//     This is the priority the refresh previously lacked.
//   - When the last outstanding reservation is released the intent is DRAINED,
//     and the refresh proceeds to sample, arm, and pin. Because the intent is
//     still held, the pin arms over an item on which no reservation can have
//     appeared: the intent becomes the pin without ever reopening the door.
//
// Contention is then a WAIT under the refresh transaction's own bounded
// context, not a consumed retry, and failCoherence is left for the thing it
// should always have meant: genuine no-progress.
//
// ── AND THE INTENT IS NOT ITS OWN QUEUE ─────────────────────────────────────
//
// The intent says who must WAIT. It says nothing about who goes NEXT, and for
// one round that was the same thing only by accident: a queued mutation was
// recorded nowhere, so when the intent was released the item went to whichever
// waiter reached a.mu first — and the next pass in a refresh stream, woken
// directly by the per-stripe kernel-refresh gate, is not even waiting on the
// same channel the mutation is. Sustained invalidations then starved every
// writer on the item for its whole deadline.
//
// So an intent is TAKEN and RELEASED through the item's one arrival order
// (itemturnstile.go), which covers refresh intents and mutation reservations
// alike. Everything above is preserved exactly — this pass still waits pre-lock
// holding nothing, still drains the reservations outstanding when it was
// granted, and still escalates on the same two bounds — and the item now moves
// to the head of a written-down queue instead of to whoever wakes up fastest.
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

// acquireRefreshIntent takes this pass's place in the item's arrival order,
// registers its intent when the item is handed to it, and returns once every
// reservation that was outstanding at that moment has drained.
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
	a.mu.Lock()
	ticket := a.takeItemTicketLocked(itemID, ticketRefresh)
	a.advanceItemQueueLocked(itemID)
	a.mu.Unlock()
	if !a.awaitItemTicket(ctx.Done(), itemID, ticket, nil) {
		return nil, fmt.Errorf(
			"portablefsd: refresh intent for item %d: %w", itemID, ctx.Err(),
		)
	}
	// The grant IS the installed intent (advanceItemQueueLocked): from the
	// instant it was published every ARRIVING size mutation on the item queues
	// behind this pass, and whatever was already outstanding drains below on its
	// own terms.
	intent := ticket.intent
	release := func() { a.releaseRefreshIntent(itemID, intent) }
	if ctx.Err() != nil {
		// Granted at the same moment the transaction died. Give the item back
		// rather than leaving a pending intent behind a pass that will not run.
		release()
		return nil, fmt.Errorf(
			"portablefsd: refresh intent for item %d: %w", itemID, ctx.Err(),
		)
	}
	drainCtx, cancelDrain := context.WithTimeout(ctx, refreshIntentDrainBudget)
	defer cancelDrain()
	select {
	case <-intent.drained:
		return release, nil
	case <-drainCtx.Done():
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

// releaseRefreshIntent gives the item up and hands it to the next claim in
// arrival order INSIDE THE SAME a.mu HOLD.
//
// That single hold is the whole of finding 1. Deleting the intent and then
// letting whoever reaches a.mu first take the item is what let the next refresh
// pass — woken directly by the per-stripe kernel-refresh gate — install the
// following intent before an already-queued mutation could retry, for as long
// as invalidations kept arriving. See itemturnstile.go.
//
// The intent's own waiters are woken outside the hold for the ordinary reason:
// a woken waiter's first act is to take a.mu.
func (a *attach) releaseRefreshIntent(itemID uint64, intent *refreshIntent) {
	if intent == nil {
		return
	}
	intent.release.Do(func() {
		a.mu.Lock()
		if a.refreshIntents[itemID] == intent {
			delete(a.refreshIntents, itemID)
		}
		a.advanceItemQueueLocked(itemID)
		a.mu.Unlock()
		close(intent.done)
	})
}
