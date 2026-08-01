package portablefsd

// THE ITEM-SCOPED SIZE-MUTATION TOKEN.
//
// ── WHAT THE MUTATION SEQUENCE STILL COULD NOT SAY ──────────────────────────
//
// The per-item mutation sequence (mutationseq.go) made a committed-but-
// unpublished size visible to a refresh pass, and the refresh window's
// classifier learned to call a mutation that STARTS while a window is open
// ambiguous. Both are CHECKS, and a check answers only about the past: it
// detects a mutation that began before it ran. Neither of them orders anything
// against the syscall the refresh is inside.
//
// The interleaving that survives is the one where nothing is checked at all
// after the last check:
//
//	1. a refresh pass proves its sample current under a.mu, arms its pinned
//	   window, and enters unix.Ftruncate(fd, S);
//	2. the kernel turns that into a setattr upcall; the handler reaches its
//	   phase-3 revalidation, observes no mutation in flight, answers the upcall
//	   locally and RETURNS — releasing every lock it held;
//	3. before the Swift callback carrying that answer returns to the kernel, and
//	   therefore before the original Ftruncate has completed, another callback on
//	   the same item opens its own mutation sequence and COMMITS an extension to
//	   N > S. The application is told the bytes are durable;
//	4. only now does Ftruncate(S) complete, shortening the kernel's vnode back
//	   over an extension that has already been acknowledged.
//
// Every check in step 2 was true when it ran. The mutation of step 3 started
// after all of them. A stronger check placed anywhere before the syscall
// completes cannot close this: the gap is not a missing observation, it is a
// missing ORDER.
//
// ── THE TOKEN, AND WHY IT IS A LINEARIZATION POINT ──────────────────────────
//
// So the refresh's ftruncate is made exclusive against every size mutation on
// the item it names, and the exclusion is established by a token rather than
// by a predicate:
//
//   - A size mutation RESERVES the item before it may proceed. The reservation
//     is taken at the daemon's one pre-lock admission point and released when
//     its handler has finished — so it strictly contains the whole of that
//     handler's commit and publication.
//   - A refresh PINS the item, under a.mu, in the same critical section that
//     opens its provenance window, and holds the pin until unix.Ftruncate has
//     returned. It never arms while any reservation is outstanding.
//   - A mutation that finds a pin installed WAITS for it.
//   - And before any of that, a refresh declares an INTENT on the item, so the
//     reservations it must not arm over DRAIN while later ones queue behind it
//     (refreshintent.go). Without the intent the second bullet had no
//     counterpart: the refresh could only refuse and retry, and ordinary
//     contention exhausted its budget into a terminal coherence failure.
//
// Both sides transition under a.mu, so for any (refresh, mutation) pair exactly
// one of two things is true: the reservation was visible when the refresh
// declared its intent — and the refresh waited for it, which is an ordinary
// ordering outcome — or the intent or the pin was visible when the mutation
// tried to reserve, and the mutation is behind the syscall. There is no third
// state, and in particular there is no state in which a commit lands between
// the last check and the completion of the ftruncate. The ftruncate becomes the
// linearization point it always claimed to be.
//
// Both halves of a window are also torn down together, under one a.mu hold
// (retireRefreshWindowLocked): a marker outliving its pin is a provenance claim
// with nothing behind it, and an application truncate arriving in that interval
// was answered as the daemon's own bookkeeping.
//
// ── WHY THE WAIT IS PRE-LOCK, AND WHY THAT IS NOT NEGOTIABLE ────────────────
//
// The wait is bounded by the refresh's own syscall, which is local and fast —
// but only if the daemon can SERVICE the upcall that syscall produces. That
// upcall is an ordinary frontend setattr: it takes a.nsMu.RLock, a handle gate
// and a.mu on its way to being answered locally.
//
// A waiter that already held a.nsMu.RLock would therefore deadlock the moment
// any namespace-exclusive request queued behind it: Go's RWMutex is
// writer-preferring, so the queued writer blocks the refresh upcall's own
// RLock, the upcall never completes, the ftruncate never returns, the pin is
// never released, and the waiter never proceeds. The wait must therefore
// happen where every other unbounded step in this daemon happens — at
// attach.admitRequest, holding no frontend lock at all (mutationadmit.go).
//
// It is placed AFTER the lane admission it accompanies, not before: a credit or
// metadata-lane park is unbounded by design, and a reservation held across one
// would refuse every refresh on the item for the duration of the backlog. What
// the reservation spans is exactly what it must — the frontend locks, the
// commit, and the publication — and nothing that waits on the uplink.
//
// The daemon's OWN refresh upcall never reserves. It is a size-bearing setattr
// like any other, so it is excluded by the frozen phase-1 provenance verdict
// rather than by a shape test: a request phase 1 did not call an application
// mutation neither commits anything nor may be made to wait for the syscall it
// is itself completing.

import (
	"context"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// refreshPin is one pinned refresh's ownership of an item's size, held for
// exactly the extent of the unix.Ftruncate(2) it brackets.
//
// done is closed — never sent on — so any number of waiters observe the release
// without the releaser knowing how many there are.
type refreshPin struct {
	done chan struct{}
	once sync.Once
}

func (p *refreshPin) release() {
	if p == nil {
		return
	}
	p.once.Do(func() { close(p.done) })
}

// installRefreshPinLocked takes the item's size for the caller's ftruncate and
// returns the pin. Callers hold a.mu, and must have already established that no
// reservation is outstanding (refreshSampleSupersededLocked).
//
// It is deliberately NOT paired with a release closure of its own. A window is
// torn down by retireRefreshWindowLocked, which removes this pin and the
// provenance marker together — see there for why they may not be two steps.
func (a *attach) installRefreshPinLocked(itemID uint64) *refreshPin {
	if itemID == 0 {
		return nil
	}
	if a.refreshPins == nil {
		a.refreshPins = map[uint64]*refreshPin{}
	}
	pin := &refreshPin{done: make(chan struct{})}
	a.refreshPins[itemID] = pin
	return pin
}

// pinRefreshItemLocked is installRefreshPinLocked plus the standalone release
// that the pin-only tests drive. Production code arms a pin only as half of a
// window and therefore always goes through retireRefreshWindowLocked.
func (a *attach) pinRefreshItemLocked(itemID uint64) func() {
	pin := a.installRefreshPinLocked(itemID)
	if pin == nil {
		return func() {}
	}
	return func() {
		a.mu.Lock()
		if a.refreshPins[itemID] == pin {
			delete(a.refreshPins, itemID)
		}
		a.mu.Unlock()
		pin.release()
	}
}

// retireRefreshWindowLocked removes BOTH halves of one refresh window — the
// provenance marker bound to p under seq, and the item's pin — inside the
// caller's single a.mu hold, and returns the pin so its waiters are woken only
// after that hold is released.
//
// ── WHY THIS IS ONE STEP AND NOT TWO ────────────────────────────────────────
//
// The two halves state the same fact from opposite ends. The marker says "the
// daemon is inside its own ftruncate(2) for this (item, size)"; the pin is what
// MAKES that true, because it is the only thing holding an application size
// mutation on the item behind that syscall.
//
// Retiring them in separate critical sections left an interval in which the
// marker was still installed and the pin was already gone, and that interval is
// not benign. A size-set matching (item, S) admitted inside it takes no wait —
// nothing is pinned — and phase 1 reads the still-pinned marker, calls the
// request daemon bookkeeping, and FREEZES that verdict (the freeze is
// one-directional by design: a non-application verdict can never be promoted
// later). The request takes no reservation, the handler answers it locally, and
// a real application truncate has been silently converted into refresh
// bookkeeping: the authority never sees it, and the mutation and version
// ordering it owed every other observer never happens.
//
// The ORDER within the hold does not matter, because no observer can see
// between them; that they share one hold is the whole point. The pin's waiters
// are woken outside it for the ordinary reason — a woken waiter's first act is
// to take a.mu.
//
// pin names the exact pin the caller installed. A nil pin retires whichever pin
// the item currently carries, which is what the belt-and-braces sweep in
// applyKernelRefresh needs: it is repairing a window whose own teardown did not
// run, so it has no pin identity to match.
func (a *attach) retireRefreshWindowLocked(
	p string,
	seq uint64,
	itemID uint64,
	pin *refreshPin,
) *refreshPin {
	if current, exists := a.expectedTruncates[p]; exists && current.seq == seq {
		delete(a.expectedTruncates, p)
	}
	if itemID == 0 {
		return nil
	}
	held := a.refreshPins[itemID]
	if held == nil || (pin != nil && held != pin) {
		return nil
	}
	delete(a.refreshPins, itemID)
	return held
}

// sizeMutationReservedLocked reports whether a size mutation has been admitted
// for itemID and has not finished. Callers hold a.mu in either mode.
func (a *attach) sizeMutationReservedLocked(itemID uint64) bool {
	return a.sizeMutationReservations[itemID] > 0
}

// reserveSizeMutation is the mutation half of the token. It waits out any
// pinned refresh on itemID — and any refresh that has declared an INTENT on it
// but has not pinned yet (refreshintent.go) — and then registers this mutation,
// returning the release.
//
// Waiting for the intent as well as the pin is what makes the protocol FAIR.
// Without it a refresh had no claim of its own: it could only re-check what was
// reserved at each of its 41 ticks, so a stream of ordinary overlapping writers
// starved it out of its whole budget and the failure was terminal at its caller.
//
// The wait is bounded by ctx — the request's own operation deadline — and its
// refusal is EINTR, which is honest: nothing has been attempted, and the
// interrupted-syscall retry runs the whole admission again. It is deliberately
// NOT bounded by a shorter private timer that would expire while a pin was
// still live: giving up on the wait means proceeding to commit inside somebody
// else's ftruncate, which is the exact event this exists to make impossible.
//
// A zero itemID is an item the registry cannot name, so no refresh can be
// carrying a sample of it and the reservation is inert.
func (a *attach) reserveSizeMutation(ctx context.Context, itemID uint64) (func(), int32) {
	if itemID == 0 {
		return nil, 0
	}
	for {
		a.mu.Lock()
		blocked := a.refreshIntentBlockerLocked(itemID)
		if blocked == nil {
			if a.sizeMutationReservations == nil {
				a.sizeMutationReservations = map[uint64]int{}
			}
			a.sizeMutationReservations[itemID]++
			a.mu.Unlock()
			return a.releaseSizeMutationOnce(itemID), 0
		}
		a.mu.Unlock()
		select {
		case <-blocked:
		case <-ctx.Done():
			return nil, darwinEINTR
		}
	}
}

func (a *attach) releaseSizeMutationOnce(itemID uint64) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			if n := a.sizeMutationReservations[itemID]; n <= 1 {
				delete(a.sizeMutationReservations, itemID)
			} else {
				a.sizeMutationReservations[itemID] = n - 1
			}
			// A pending refresh is waiting for exactly this: the last
			// reservation that was outstanding when it declared its intent.
			a.signalRefreshIntentDrainLocked(itemID)
			a.mu.Unlock()
		})
	}
}

// sizeMutationItem names the item a request is about to move the size of, and
// is the whole definition of "size mutation" for the token: exactly the set of
// requests that reach attach.beginItemMutation.
//
// The operands are resolved from the item registry under a.mu alone, never
// blocking, exactly as the rest of pre-lock admission resolves its operands. A
// request whose object does not resolve right now takes no reservation — the
// handler answers it on its own terms under the locks, and it commits nothing
// on the way there.
func (a *attach) sizeMutationItem(body any) (uint64, bool) {
	switch req := body.(type) {
	case *pfslocal.WriteRequest:
		h, eno := a.handle(req.Handle)
		if eno != 0 || h == nil {
			return 0, false
		}
		return h.itemID, h.itemID != 0
	case *pfslocal.SetAttrRequest:
		if req.Size == nil {
			return 0, false
		}
		target, eno := a.objectTarget(req.Item, req.Handle)
		if eno != 0 || target.rec == nil {
			return 0, false
		}
		return target.rec.item.ItemID, target.rec.item.ItemID != 0
	}
	return 0, false
}

// reserveSizeMutationForRequest is admitRequest's half of the token: it decides
// whether this request is a size mutation that must be ordered against a pinned
// refresh, and if so takes the reservation.
//
// ctx is the ADMISSION context, so the frozen phase-1 provenance verdict is
// already on it for every size-bearing setattr. That is what excludes the
// daemon's own refresh upcall, and it is the same verdict the handler consumes
// — never a second, independently derived one.
func (a *attach) reserveSizeMutationForRequest(
	ctx context.Context,
	body any,
) (func(), int32) {
	if req, ok := body.(*pfslocal.SetAttrRequest); ok {
		if verdict, known := a.frozenRefreshVerdict(ctx, req); known &&
			verdict.class != refreshClassApplication {
			// The daemon's own kernel-state refresh. It commits nothing, and
			// making it wait for the pin would make it wait for the syscall it
			// is itself the upcall of.
			return nil, 0
		}
	}
	itemID, ok := a.sizeMutationItem(body)
	if !ok {
		return nil, 0
	}
	return a.reserveSizeMutation(ctx, itemID)
}
