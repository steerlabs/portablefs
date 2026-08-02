package portablefsd

// THE PER-ITEM TURNSTILE: ONE ORDER FOR REFRESHES AND MUTATIONS ALIKE.
//
// ── WHAT ONE-DIRECTIONAL FAIRNESS COST ──────────────────────────────────────
//
// The refresh intent (refreshintent.go) gave a pending refresh the claim it had
// never had: arriving size mutations queue behind it, so ordinary contention
// stopped exhausting the refresh's budget into a terminal coherence failure.
//
// It gave that claim to the refresh ONLY. A mutation that finds an intent
// installed waits on a channel and nothing anywhere RECORDS that it is waiting,
// so nothing obliges the item to be handed to it when the intent goes away. The
// symmetric starvation follows immediately, and it needs no bad luck — it is
// what a stream of refresh passes does by construction:
//
//	R1 holds the intent on the item;
//	W waits on intent.done, holding no lock at all;
//	R2 is parked on the per-stripe kernel-refresh gate, waiting to start;
//	R1 releases: it deletes its intent, closes done — W is now runnable — and
//	  then releases the gate, which wakes R2 directly;
//	R2 reaches a.mu and installs the next intent before W's woken goroutine
//	  reaches a.mu at all. W queues again, having attempted nothing.
//
// Repeat for W's whole operation deadline and W returns EINTR. Under sustained
// peer invalidations — precisely when refresh passes stream — that is livelock
// by priority, and the fact that Go's close(2) happens to wake channel waiters
// in the order they blocked is a property of the runtime, not a property of
// this protocol: it disappears the moment the next refresh is waiting somewhere
// else, which on the gate it always is.
//
// ── THE TURNSTILE ───────────────────────────────────────────────────────────
//
// So arrival order is made EXPLICIT, once, for both kinds of claim on an item.
// Every refresh intent and every size-mutation reservation takes a numbered
// ticket under a.mu, and the item is handed to the HEAD of that queue — never
// to whoever happens to reach a.mu first:
//
//	– tickets are issued from a per-item counter under a.mu, so arrival order is
//	  a total order and it is written down;
//	– a ticket leaves the queue only by being GRANTED at the head, or by being
//	  ABANDONED when its context dies;
//	– every event that frees the item (an intent released, a pin retired) runs
//	  the grant loop inside the SAME a.mu hold that gave the item up, so there is
//	  no instant in which the item is free and the queue is not being served.
//
// The two kinds differ only in what a grant means and in what blocks it:
//
//	MUTATION  grant = one reservation. Blocked while an intent or a pin is
//	          installed, which is exactly the pre-existing rule.
//	REFRESH   grant = the intent installed. Blocked while another intent or a
//	          pin is installed — and NOT by outstanding reservations, because a
//	          refresh must be able to declare its intent over them and then wait
//	          for them to drain. That is the whole shape of refreshintent.go and
//	          it is preserved exactly.
//
// ── WHY THIS IS A FAIRNESS PROOF AND NOT A HOPE ─────────────────────────────
//
//  1. TOTAL ORDER. Ticket numbers are issued under a.mu and the queue is kept
//     in issue order. For any two claims on one item, which arrived first is a
//     fact, not a scheduling outcome.
//
//  2. HEAD-ONLY SERVICE. advanceItemQueueLocked grants only the head. A claim
//     with ticket k is therefore preceded by at most the k-1 claims that
//     arrived before it, and by nothing that arrives after.
//
//  3. THE HEAD ALWAYS MAKES PROGRESS. A head ticket is blocked only by an
//     installed intent or pin, and both are bounded by the pass that holds them
//     — the intent by refreshIntentDrainBudget, the pin by the local ftruncate
//     it brackets. A head mutation ticket is never blocked by other mutations
//     (reservations are counted, not exclusive), and a head refresh ticket is
//     never blocked by outstanding reservations (it installs over them and
//     drains them afterwards). So no head waits on something with no bound.
//
//  4. NOTHING WAITS HOLDING ANYTHING. A ticket is taken and awaited at exactly
//     the two places the old channel waits happened: pre-lock admission for a
//     mutation (mutationadmit.go) and before the refresh pass samples anything.
//     Both hold no frontend lock, so the queue can never be part of a cycle.
//
//  5. CANCELLATION CANNOT WEDGE IT. A waiter whose context dies removes its own
//     ticket and re-runs the grant loop under a.mu before returning; if it lost
//     the race and was granted anyway, it gives the grant back through the same
//     release the normal path uses. Either way the item's turn moves on.
//
// The escalation boundaries are unchanged, and deliberately so: a mutation's
// wait is still bounded by its operation deadline and still refuses with EINTR
// having attempted nothing, and a refresh's wait is still bounded by its
// transaction's context and the intent drain budget.

type ticketKind uint8

const (
	// ticketMutation is one admitted size mutation's claim on the item.
	ticketMutation ticketKind = iota
	// ticketRefresh is one pending refresh pass's claim on the item.
	ticketRefresh
)

// itemTicket is one claim's place in an item's arrival order.
//
// ready is CLOSED — never sent on — when the claim is granted, so the waiter
// observes the grant without the granter knowing anything about it.
type itemTicket struct {
	seq     uint64
	kind    ticketKind
	ready   chan struct{}
	granted bool
	// intent is the refresh intent installed by this ticket's grant, for a
	// refresh ticket. Nil for a mutation ticket.
	intent *refreshIntent
	// yielding requests a DEFERENTIAL intent for a refresh ticket: one that is
	// preempted the moment a size mutation reaches the head of the item's queue
	// behind it. Meaningless for a mutation ticket. See refreshintent.go.
	yielding bool
}

// itemTurnstile is one item's arrival order. It exists only while something is
// queued for the item.
type itemTurnstile struct {
	next  uint64
	queue []*itemTicket
}

// takeItemTicketLocked issues the next ticket for itemID. Callers hold a.mu,
// and must call advanceItemQueueLocked before releasing it — a ticket that
// reaches an idle item is granted by that call and never waits at all.
func (a *attach) takeItemTicketLocked(itemID uint64, kind ticketKind) *itemTicket {
	if a.itemTurnstiles == nil {
		a.itemTurnstiles = map[uint64]*itemTurnstile{}
	}
	ts := a.itemTurnstiles[itemID]
	if ts == nil {
		ts = &itemTurnstile{}
		a.itemTurnstiles[itemID] = ts
	}
	ts.next++
	t := &itemTicket{seq: ts.next, kind: kind, ready: make(chan struct{})}
	ts.queue = append(ts.queue, t)
	return t
}

// advanceItemQueueLocked grants as many head tickets as the item's current
// state allows, in issue order, and stops at the first one it cannot grant.
// Callers hold a.mu.
//
// It is called from every place that can make a claim grantable: taking a
// ticket, releasing an intent, retiring a pin, and abandoning a ticket. Being
// called under the same a.mu hold that gave the item up is the point — it is
// what leaves no instant for a later arrival to get ahead of an earlier one.
func (a *attach) advanceItemQueueLocked(itemID uint64) {
	ts := a.itemTurnstiles[itemID]
	if ts == nil {
		return
	}
	for len(ts.queue) > 0 {
		t := ts.queue[0]
		switch t.kind {
		case ticketMutation:
			// Exactly the pre-existing rule: an intent or a pin on the item
			// holds every size mutation behind the refresh that owns it.
			if a.refreshIntentBlockerLocked(itemID) != nil {
				// ...unless that refresh is DEFERENTIAL, in which case this is
				// the moment it agreed to give the item back. The mutation still
				// waits here — the intent has not gone away yet — but the wait is
				// now bounded by how long the pass takes to notice rather than by
				// the pass's whole transaction. See refreshintent.go.
				a.preemptRefreshIntentLocked(itemID)
				return
			}
			if a.sizeMutationReservations == nil {
				a.sizeMutationReservations = map[uint64]int{}
			}
			a.sizeMutationReservations[itemID]++
		case ticketRefresh:
			// A refresh may declare its intent OVER outstanding reservations —
			// they drain on their own terms and the pass waits for them — but
			// never over another pass's intent or pin.
			if a.refreshIntents[itemID] != nil || a.refreshPins[itemID] != nil {
				return
			}
			if a.refreshIntents == nil {
				a.refreshIntents = map[uint64]*refreshIntent{}
			}
			intent := &refreshIntent{
				done:     make(chan struct{}),
				drained:  make(chan struct{}),
				preempt:  make(chan struct{}),
				yielding: t.yielding,
			}
			a.refreshIntents[itemID] = intent
			t.intent = intent
			// From this instant every ARRIVING size mutation queues. Whatever
			// was already outstanding drains on its own terms — and if nothing
			// is outstanding the pass may proceed immediately.
			a.signalRefreshIntentDrainLocked(itemID)
		}
		ts.queue = ts.queue[1:]
		t.granted = true
		close(t.ready)
	}
	if len(ts.queue) == 0 {
		delete(a.itemTurnstiles, itemID)
	}
}

// abandonItemTicket removes a ticket whose waiter has given up and hands the
// item to whatever is behind it. It reports whether the ticket had already been
// granted, in which case the caller owns the grant and must give it back.
func (a *attach) abandonItemTicket(itemID uint64, t *itemTicket) (granted bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if t.granted {
		return true
	}
	ts := a.itemTurnstiles[itemID]
	if ts != nil {
		for i, queued := range ts.queue {
			if queued == t {
				ts.queue = append(ts.queue[:i:i], ts.queue[i+1:]...)
				break
			}
		}
		// The head may have been this ticket, and the one behind it may be
		// grantable right now.
		a.advanceItemQueueLocked(itemID)
	}
	return false
}

// awaitItemTicket blocks until the ticket is granted or the wait is abandoned.
// It holds no lock, which is the property every caller depends on.
//
// granted reports the outcome; when it is false the caller has no claim on the
// item and never had one.
func (a *attach) awaitItemTicket(
	done <-chan struct{},
	itemID uint64,
	t *itemTicket,
	queued func(),
) (granted bool) {
	a.mu.RLock()
	already := t.granted
	a.mu.RUnlock()
	if already {
		return true
	}
	if queued != nil {
		queued()
	}
	select {
	case <-t.ready:
		return true
	case <-done:
		return a.abandonItemTicket(itemID, t)
	}
}

// itemTicketsQueued reports how many claims are waiting for an item. It exists
// for assertions — production code never asks.
func (a *attach) itemTicketsQueued(itemID uint64) int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if ts := a.itemTurnstiles[itemID]; ts != nil {
		return len(ts.queue)
	}
	return 0
}
