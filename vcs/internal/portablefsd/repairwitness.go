package portablefsd

// THE CROSSED REPAIR'S CONVERGENCE WITNESS.
//
// A crossed-scope repair (coherence_refresh.go) has two honest ways to end: it
// refreshes the kernel itself, or it observes that the APPLICATION has already
// restated the item to the kernel and therefore has nothing left to add. The
// second is what keeps a continuously written file from walking the whole
// ten-minute budget down to the give-up path, and it is a proof rather than a
// shrug — but only if the thing it observes is really the mutation that took
// the item away from the repair.
//
// ── WHAT THE PREVIOUS WITNESS ACTUALLY PROVED (NOTHING) ─────────────────────
//
// It counted ANY attribute assignment on the item that happened while ANY size
// reservation existed:
//
//	noteRepairPublicationLocked(itemID):
//	    if watched(itemID) && sizeMutationReservedLocked(itemID) { count++ }
//
// Both halves are ambient facts about the item, and neither of them is a fact
// about a mutation. The interleaving that breaks it needs no bad luck:
//
//	1. a getattr for the item is ALREADY IN FLIGHT — it took a.nsMu.RLock and
//	   the handle gate before any of this started;
//	2. the repair yields to write W, so the repair believes "the writer is live
//	   and its own publications drive the kernel";
//	3. W is granted its reservation at pre-lock admission, and then queues
//	   behind the getattr's locks, having committed nothing;
//	4. the getattr completes and publishes its PRE-WRITE observation. The
//	   reservation exists, so the counter increments;
//	5. the repair sees a publication and exits "discharged";
//	6. W is cancelled, refused, or fails before it commits anything.
//
// No post-crossing size mutation ever reached the kernel, and the coherence
// debt was thrown away on a publication that carried the value the repair was
// trying to correct.
//
// ── THE TOKEN ───────────────────────────────────────────────────────────────
//
// So the witness stops asking "was something reserved" and starts asking "did
// THE MUTATION THAT PREEMPTED ME tell the kernel". A size mutation is issued a
// TOKEN at the instant its reservation is GRANTED (refreshpin.go), the token
// travels on the request's own operation context, and exactly one thing
// increments the item's generation:
//
//	– the handler has COMMITTED and published its post-op size into the
//	  registry (markSizeMutationPublished, called from the two publication
//	  sites in ops.go), AND
//	– that publication has been DELIVERED to the frontend as this request's
//	  reply, un-retracted (noteSizeMutationDelivered, called from the
//	  dispatcher once the frame is on the wire).
//
// A publication by anything without a token — a getattr, a reconciliation
// install, a background repair — increments nothing, whatever is reserved at
// the time. A mutation that takes its reservation and then fails, is cancelled,
// or answers an errno increments nothing either: it has a token and never
// publishes, or publishes and is never delivered.
//
// ── THE GENERATION, AND WHY IT IS NOT A COUNTER PER WATCHER ─────────────────
//
// The old state was `map[itemID]uint64` written as `= 0` by every watcher and
// `delete`d by every stop. Two repairs on one item — which is ordinary: a
// disconnect repair and a crossing repair can name the same item, and
// refreshCrossedItems is called from three places — corrupted each other in
// both directions. The later watcher RESET the earlier one's count, so an
// earlier repair lost publications it had already been told about; and either
// watcher's stop DELETED the shared entry, so the survivor stopped counting
// silently and ran to its give-up path.
//
// The generation is monotonic per item instead, and each watcher records the
// BASELINE it saw when it armed. Watchers are refcounted, so an entry lives
// exactly as long as some repair is watching the item — the map is still the
// size of the in-flight repair set, never of the working set — and a stop
// removes only its own reference.

import (
	"context"
	"sync"
	"sync/atomic"
)

// sizeMutationToken is ONE admitted size mutation's identity, minted when the
// item's turnstile grants its reservation and carried on that request's
// operation context for the rest of the request.
//
// It is what makes a publication attributable. Without it the witness can only
// observe that a reservation existed somewhere on the item, which is a
// statement about the item and not about any mutation.
type sizeMutationToken struct {
	itemID uint64
	// published records that this mutation committed and installed its post-op
	// size into the registry. It is set under no lock in particular — the
	// publication sites hold a.mu, the reader does not — so it is atomic.
	published atomic.Bool
	// counted keeps one mutation from bumping the item's generation twice. A
	// request that unwinds and re-admits takes a NEW token, so this guards only
	// against a single token being delivered more than once.
	counted atomic.Bool
}

type sizeMutationTokenKey struct{}

// withSizeMutationToken puts the granted reservation's token on the operation
// context every handler for this request runs under.
func withSizeMutationToken(ctx context.Context, tok *sizeMutationToken) context.Context {
	if tok == nil {
		return ctx
	}
	return context.WithValue(ctx, sizeMutationTokenKey{}, tok)
}

// sizeMutationTokenFrom answers the token this request holds, or nil for a
// request that is not a size mutation — which is every publisher the witness
// must ignore.
func sizeMutationTokenFrom(ctx context.Context) *sizeMutationToken {
	if ctx == nil {
		return nil
	}
	tok, _ := ctx.Value(sizeMutationTokenKey{}).(*sizeMutationToken)
	return tok
}

// markSizeMutationPublished records that THIS request — the one holding the
// item's reservation — has committed and installed its post-op size into the
// registry.
//
// It is deliberately only half of the witness. The registry agreeing with the
// engine says nothing about what the KERNEL was told; that is what the reply
// says, and noteSizeMutationDelivered is where the reply is accounted for.
func markSizeMutationPublished(ctx context.Context) {
	if tok := sizeMutationTokenFrom(ctx); tok != nil {
		tok.published.Store(true)
	}
}

// sizeMutationPublished reports whether this request's mutation has reached its
// committed registry publication. It exists for the dispatcher's delivery step
// and for assertions.
func sizeMutationPublished(ctx context.Context) bool {
	tok := sizeMutationTokenFrom(ctx)
	return tok != nil && tok.published.Load()
}

// noteSizeMutationDelivered is the ONE place an item's committed-publication
// generation advances.
//
// It is called by the dispatcher once a request's reply frame has been written
// and was not retracted, which is exactly the point at which this daemon's own
// post-op attributes have travelled to the kernel by the ordinary reply path.
// A reply that carried an errno never reaches it (the handler published a
// commit the kernel is not being told about, which is precisely a debt the
// repair must still pay); a reply the daemon retracted never reaches it either,
// because the frontend discards a retracted operation's values wholesale.
func (a *attach) noteSizeMutationDelivered(ctx context.Context) {
	tok := sizeMutationTokenFrom(ctx)
	if tok == nil || tok.itemID == 0 || !tok.published.Load() {
		return
	}
	if !tok.counted.CompareAndSwap(false, true) {
		return
	}
	a.mu.Lock()
	if w := a.repairPublicationWatches[tok.itemID]; w != nil {
		w.gen++
	}
	a.mu.Unlock()
}

// repairPublicationWatch is one item's shared witness state: the monotonic
// generation of delivered, committed size publications, and how many repairs
// are currently watching it.
//
// Guarded by attach.mu.
type repairPublicationWatch struct {
	refs int
	gen  uint64
}

// repairPublicationWatcher is ONE repair's view of that state. Its baseline is
// the generation it observed when it armed, so concurrent repairs on the same
// item cannot reset or delete each other.
type repairPublicationWatcher struct {
	a        *attach
	itemID   uint64
	baseline uint64
	once     sync.Once
}

// watchRepairPublications starts one repair's witness for itemID.
//
// It is the crossed-scope repair's convergence witness. See repairCrossedItem
// for what a delivered publication proves and why.
func (a *attach) watchRepairPublications(itemID uint64) *repairPublicationWatcher {
	w := &repairPublicationWatcher{a: a, itemID: itemID}
	if itemID == 0 {
		return w
	}
	a.mu.Lock()
	if a.repairPublicationWatches == nil {
		a.repairPublicationWatches = map[uint64]*repairPublicationWatch{}
	}
	watch := a.repairPublicationWatches[itemID]
	if watch == nil {
		watch = &repairPublicationWatch{}
		a.repairPublicationWatches[itemID] = watch
	}
	watch.refs++
	w.baseline = watch.gen
	a.mu.Unlock()
	return w
}

// since reports how many delivered, committed size publications this daemon has
// made for the item since THIS watcher armed.
func (w *repairPublicationWatcher) since() uint64 {
	if w == nil || w.itemID == 0 {
		return 0
	}
	w.a.mu.RLock()
	defer w.a.mu.RUnlock()
	watch := w.a.repairPublicationWatches[w.itemID]
	if watch == nil || watch.gen <= w.baseline {
		return 0
	}
	return watch.gen - w.baseline
}

// stop drops this watcher's reference. The item's state survives while any
// other repair still holds one, which is what keeps two repairs on one item
// from silently blinding each other.
func (w *repairPublicationWatcher) stop() {
	if w == nil || w.itemID == 0 {
		return
	}
	w.once.Do(func() {
		w.a.mu.Lock()
		if watch := w.a.repairPublicationWatches[w.itemID]; watch != nil {
			watch.refs--
			if watch.refs <= 0 {
				delete(w.a.repairPublicationWatches, w.itemID)
			}
		}
		w.a.mu.Unlock()
	})
}
