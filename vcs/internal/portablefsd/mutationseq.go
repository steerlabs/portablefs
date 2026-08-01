package portablefsd

// THE PER-ITEM MUTATION SEQUENCE.
//
// ── THE HOLE IT CLOSES ──────────────────────────────────────────────────────
//
// A size mutation is two separate events, and the daemon's own registry only
// witnesses the second one:
//
//  1. THE ENGINE COMMIT. vol.Write / vol.Setattr (or, for a graft, the host
//     file's own write(2)/ftruncate(2)) returns. The extension is in the WAL,
//     the count is DECIDED, and the application is about to be told so.
//  2. THE REGISTRY PUBLICATION. The handler takes a.mu and installs the
//     post-op attributes into itemRecord.attr (writeReplyWithAttr,
//     setattr's registerLocked, controlWriteLocked).
//
// Between them the item is committed at N and the registry still says S, and
// the refresh fence — whose composed arm is exactly "itemRecord.attr.Size has
// not moved since I sampled" (refreshSampleSupersededLocked) — reads S and
// concludes nothing has happened. It then arms an Internal window and issues
// ftruncate(S) through the mount. The window predicate agrees (the registry
// still says S), the upcall is answered locally as daemon bookkeeping, and the
// kernel's vnode is shortened to S over an extension the application has
// already been told is durable. The publication of N lands a moment later into
// a registry the kernel no longer agrees with, and nothing re-states it.
//
// The registry is therefore not a sufficient witness. It is the END of a
// mutation, not the mutation, and a proof built only on it proves only that no
// mutation has FINISHED.
//
// ── THE SEQUENCE ────────────────────────────────────────────────────────────
//
// So every size mutation brackets itself with a per-item sequence:
//
//	bumped   is advanced BEFORE the engine commit is attempted.
//	settled  is advanced AFTER the registry publication has been installed.
//
// `bumped == settled` is the whole predicate, and it is a statement about the
// object rather than about any particular handler: for this item, there is no
// mutation anywhere between its commit and its publication. A refresh arms only
// from that state, so the composed size it re-reads under a.mu is the composed
// size of every acknowledged mutation, with none in flight behind it.
//
// The bracket is deliberately CONSERVATIVE at both ends. Bumping before the
// commit rather than inside it costs a refresh nothing (it retries, which is an
// ordinary outcome — see errRefreshSampleSuperseded) and needs no atomicity
// with the engine's own internals, which the frontend does not own and must not
// reach into. Settling after the publication rather than inside the same lock
// hold is the same trade in the other direction: a slightly longer refusal
// window in exchange for a bracket that is a plain defer at the top of the
// handler and therefore cannot be skipped by any early return, error path, or
// panic on the way out.
//
// ── WHAT IS BRACKETED ───────────────────────────────────────────────────────
//
// Every path that can move an item's composed size and then publish it:
//
//   - attach.write, both arms — the delegated/authority engine write and the
//     graft handle's host write(2).
//   - attach.setattr's authority arm and setattrLocal's graft arm, for a
//     size-set (a truncate is a size mutation with no bytes).
//   - controlWriteLocked, whose write+truncate+publish sequence has the same
//     shape as the kernel frontend's and the same gap in the middle.
//
// Operations that MINT an identity (create, mkdir, symlink) are not bracketed
// and need not be: a refresh pass can only carry a stale sample for an item it
// already found in the registry, and a fresh identity was not there to sample.
//
// ── WHY A COUNT AND NOT A FLAG ──────────────────────────────────────────────
//
// Two descriptors on one inode write concurrently. A flag cleared by whichever
// finishes first would declare the item stable while the other is still between
// its commit and its publication, which is precisely the state being excluded.
// The pair is a monotone sequence rather than a bare counter so the invariant
// reads as what it is — a publication has caught up with a commit — and so a
// diagnostic can say how far behind it is.
//
// ── AND WHY SETTLING TAKES A VERDICT ────────────────────────────────────────
//
// `settled` used to advance unconditionally, from a bare defer, on the theory
// that the handler had reached its publication step. It had reached the step;
// it had not necessarily PUBLISHED. Every one of these handlers refreshes its
// post-op attributes through an OPTIONAL round trip — writeReply's
// GetattrOpenHandle, the control write's trailing Getattr — and deliberately
// answers with the committed count even when that refresh fails, because the
// count is the application's only chance to learn the bytes are durable (see
// attach.writeReply). On that path the registry keeps the PRE-write size, and
// closing the sequence there hands the fence a verdict of "stable" for an item
// whose registry is provably behind its own commit: the very next refresh arms
// on the stale sample and ftruncates over the committed bytes.
//
// So the settle carries what actually happened. `published` closes the
// sequence; anything else RETAINS it, and the item stays unstable — refreshes
// for it are refused, which is an ordinary retry outcome and never data loss —
// until an ordered repair publishes attributes for it (notePublicationLocked).
type itemMutationSeq struct {
	bumped  uint64
	settled uint64
	// unpublished records that at least one commit on this item settled without
	// its post-op state reaching the registry. It is cleared only by a real
	// publication, never by another settle.
	unpublished bool
}

// beginItemMutation opens one size mutation on itemID and returns its settle.
// The settle is idempotent and must be deferred by the caller BEFORE the engine
// commit is attempted, so that no return path can leave the sequence open.
//
// The settle takes the handler's own verdict: true when the item's post-op
// state reached the registry, false when the handler is returning without
// having published it. See itemMutationSeq.
//
// A zero itemID is an item the registry cannot name; there is nothing for a
// refresh to hold a stale sample of, so the bracket is inert.
func (a *attach) beginItemMutation(itemID uint64) func(published bool) {
	if itemID == 0 {
		return func(bool) {}
	}
	a.mu.Lock()
	a.beginItemMutationLocked(itemID)
	a.mu.Unlock()
	var once bool
	return func(published bool) {
		if once {
			return
		}
		once = true
		a.mu.Lock()
		a.settleItemMutationLocked(itemID, published)
		a.mu.Unlock()
	}
}

// beginItemMutationLocked advances the item's bumped sequence. Callers hold
// a.mu.
func (a *attach) beginItemMutationLocked(itemID uint64) {
	if itemID == 0 {
		return
	}
	if a.itemMutations == nil {
		a.itemMutations = map[uint64]itemMutationSeq{}
	}
	seq := a.itemMutations[itemID]
	seq.bumped++
	a.itemMutations[itemID] = seq
}

// settleItemMutationLocked advances the item's settled sequence, and drops the
// entry once publication has caught up with every commit. Callers hold a.mu.
//
// published is the handler's verdict about its OWN commit; see itemMutationSeq.
func (a *attach) settleItemMutationLocked(itemID uint64, published bool) {
	if itemID == 0 {
		return
	}
	seq, ok := a.itemMutations[itemID]
	if !ok {
		return
	}
	seq.settled++
	if !published {
		seq.unpublished = true
	}
	if seq.settled >= seq.bumped && !seq.unpublished {
		// Equal is the stable state, and the map is a set of UNSTABLE items
		// only: retaining an entry whose two halves agree would make the map
		// grow with the working set for no proof it does not already carry.
		delete(a.itemMutations, itemID)
		return
	}
	a.itemMutations[itemID] = seq
}

// notePublicationLocked is the ORDERED REPAIR for an item whose commit settled
// without publishing.
//
// It is called from the one place every attribute assignment into the registry
// now goes through (attach.publishRecordAttrLocked), so the repair is whatever
// publisher next states this item's attributes — a getattr, the next write's
// own post-op refresh, a reconciliation install. Until one arrives the item
// stays unstable and no refresh may arm a truncate window over it, which is the
// safe direction: a refused refresh retries, a truncate over committed bytes
// does not come back. Callers hold a.mu.
func (a *attach) notePublicationLocked(itemID uint64) {
	if itemID == 0 {
		return
	}
	seq, ok := a.itemMutations[itemID]
	if !ok || !seq.unpublished {
		return
	}
	seq.unpublished = false
	if seq.settled >= seq.bumped {
		delete(a.itemMutations, itemID)
		return
	}
	a.itemMutations[itemID] = seq
}

// itemMutationInFlightLocked reports whether any size mutation on itemID has
// committed (or is about to) without yet having published. Callers hold a.mu in
// either mode.
func (a *attach) itemMutationInFlightLocked(itemID uint64) bool {
	seq, ok := a.itemMutations[itemID]
	return ok && (seq.bumped != seq.settled || seq.unpublished)
}
