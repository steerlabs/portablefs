package portablefsd

import (
	"context"
	"log"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// Reconciling the retained aliases of a reincarnated pathname.
//
// ── WHAT THE DEBT IS ────────────────────────────────────────────────────────
//
// A remote rename-over replaces WHO a name identifies while the displaced inode
// stays alive behind its other links. Two independent paths carry that one event
// to the frontend:
//
//	the publisher that resolves the name -> publishes the replacement Item
//	the INVALIDATION stream's RelatedInos fan-out -> refreshes the aliases
//
// Nothing ordered them. When a publisher reached the authority directly it could
// publish the new `a` while `b` was still serving the attribute snapshot taken at
// hard-link time — new identity, Nlink=2, an impossible pair for an application
// to observe. (Round 5 did not create this hole; it removed the incidental
// serialization that used to hide it. Before that split, a lookup entered the
// publication gate BLOCKING, before its handler ran, which paid for the
// invalidation to land often enough that the race was invisible. See the
// publication activation protocol in coherence_refresh.go.)
//
// So detachReincarnatedPathLocked records a DEBT for every retained alias, and
// the publisher discharges it before its reply leaves. This is ordering, not
// polling: the debt is recorded synchronously under a.mu, and it is settled
// before the reply is written.
//
// ── WHY A TICKET AND NOT A BAG ──────────────────────────────────────────────
//
// The debt used to be one per-attach set drained by a destructive, unfiltered
// take-all. Nothing in that shape encoded an OWNER, and every consequence of
// that followed:
//
//   - CROSS-PUBLISHER THEFT. Publisher A recorded debt, released a.mu, and
//     publisher B's take-all drained it. A's own take then returned nothing, so
//     A published its replacement with A's aliases still unreconciled — while B,
//     which had no idea what it had taken, "settled" work it did not own and
//     could abandon at any of the loop's silent `continue`s.
//   - SILENT DISCARD. Taken-but-unreconcilable debt was dropped on the floor
//     with no way to re-record it, because the take had already destroyed it.
//   - RE-ENTRANT ORPHANS. Debt created by the reconciliation's OWN registration
//     landed after the take and could never be seen by anyone.
//
// A ticket fixes all three at the root by naming the owner. The debt is keyed by
// alias, but each unit of work carries a GENERATION, and a ticket records the
// generation its own registration created. A publisher settles exactly the
// (alias, generation) pairs it minted; a publisher that minted none holds a nil
// (inert) ticket and pays nothing; and two publishers that mint debt for the
// same alias coalesce onto one attempt and BOTH wait for its completion rather
// than one taking and the other proceeding blind.
//
// ── WHO ARMS, AND WHO IS EXEMPT ─────────────────────────────────────────────
//
// Every registration that can reach registerWithItemLocked's replacement branch
// is armed by its publisher and settles its ticket before its reply leaves:
// lookup, enumerate (one ticket per page), getattr, setattr, the write reply's
// post-op refresh, create/mkdir/symlink, the resolve-time root registration, the
// activation root registration, and both control-plane writers.
//
// The exemptions are structural, not oversights. The GRAFT arms of getattr,
// setattr, lookup and enumerate register through registerLocalLocked, which
// passes authIno=false — and the replacement branch tests authIno, so a
// machine-local identity can never reach it. registerSyntheticRootLocked is
// exempt for the reason stated at its own definition.
//
// recordReincarnationDebtLocked LOGS when it is reached unarmed, so a new call
// site that slipped through announces itself instead of showing up later as an
// impossible attribute pair.
//
// ── LOCK ORDER ──────────────────────────────────────────────────────────────
//
// Reconciliation issues authority RPCs, so every RPC happens with a.mu RELEASED.
// a.mu is taken only to claim the work, and again to install the result. The
// waiting arm parks on a channel while holding nothing.
//
// The install runs inside Volume.InstallOK's callback, which means it holds the
// version cache's lock too (a.mu -> VersionCache.mu). That is safe and is the
// only nesting: registerLocked takes no foreign lock — NodeState's authority-ino
// binding is a lock-free CAS — so nothing can be holding a lock this callback
// needs while waiting for the version cache.

// aliasReconcileState is the per-alias unit of work. Guarded by a.mu.
//
// needGen is bumped by every reincarnation that displaces this alias's inode;
// doneGen records the highest need a completed attempt satisfied. A ticket that
// captured needGen == N is satisfied the moment doneGen >= N — which is what
// lets two publishers share one RPC instead of racing two.
type aliasReconcileState struct {
	needGen uint64
	doneGen uint64
	// running is set while exactly one publisher is off doing the refresh with
	// a.mu released. settled is closed (and replaced) when that attempt
	// finishes, whatever its outcome, so a waiter always re-evaluates against
	// fresh state rather than trusting the runner to have succeeded.
	running bool
	settled chan struct{}
}

// reincarnationTicket is one publisher's OWNED reconciliation debt: the exact
// (alias, generation) pairs its own registration created. A nil ticket is the
// inert one every registration that displaced nothing receives.
//
// need is guarded by a.mu, like the state map it indexes: it is written by
// recordReincarnationDebtLocked (already under a.mu) and by the settle loop's
// own bookkeeping, which takes a.mu for exactly that reason.
type reincarnationTicket struct {
	a    *attach
	need map[string]uint64
}

// reincarnationOwnerScope saves the enclosing owner so ownership can nest. It
// nests for one real reason: the settle loop registers the refreshed alias, and
// a refresh can itself discover a further reincarnation. That newly created debt
// must join the SAME ticket rather than becoming an orphan nobody owns.
type reincarnationOwnerScope struct {
	armed    bool
	ticket   *reincarnationTicket
	settling bool
}

// reincarnationSettleAttempts bounds how many times one alias may be re-attempted
// inside a single settle. The loop is a fixed-point iteration (a refresh can mint
// fresh debt for the same alias, and a coalesced waiter re-checks after the
// runner finishes), so it needs a terminating bound that is not "until it works".
// Exhausting it is treated exactly like a transient failure: the debt is
// RETAINED and the publishing operation fails, never "published anyway".
const reincarnationSettleAttempts = 8

// beginReincarnationOwnerLocked arms debt attribution for the registration(s)
// about to run under a.mu. Pass nil to mint a fresh ticket on demand, or an
// existing ticket to add to it. Callers hold a.mu.
func (a *attach) beginReincarnationOwnerLocked(t *reincarnationTicket) reincarnationOwnerScope {
	saved := reincarnationOwnerScope{
		armed:    a.reincarnationArmed,
		ticket:   a.reincarnationOwner,
		settling: a.reincarnationSettling,
	}
	a.reincarnationArmed, a.reincarnationOwner = true, t
	return saved
}

// beginReincarnationSettleLocked arms the reconciliation's OWN install. It is
// the one registration over an indebted alias that must not mint further debt
// for it: that registration IS the payment, so treating it as another publisher
// arriving over unsettled state would bump the requirement it is in the middle
// of satisfying and the alias would never converge. Callers hold a.mu.
func (a *attach) beginReincarnationSettleLocked(t *reincarnationTicket) reincarnationOwnerScope {
	saved := a.beginReincarnationOwnerLocked(t)
	a.reincarnationSettling = true
	return saved
}

// endReincarnationOwnerLocked disarms and returns the ticket the enclosed
// registrations created — nil when they created no debt at all, which is the
// overwhelmingly common case and costs nothing. Callers hold a.mu.
func (a *attach) endReincarnationOwnerLocked(saved reincarnationOwnerScope) *reincarnationTicket {
	t := a.reincarnationOwner
	a.reincarnationArmed, a.reincarnationOwner = saved.armed, saved.ticket
	a.reincarnationSettling = saved.settling
	return t
}

// registerOwned is registerLocked for a publisher: it returns the record and the
// ticket owning whatever reconciliation debt THAT registration created.
func (a *attach) registerOwned(p string, attr fsproto.Attr) (*itemRecord, *reincarnationTicket) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.registerOwnedLocked(p, attr)
}

// registerOwnedLocked is registerOwned for a caller already holding a.mu.
func (a *attach) registerOwnedLocked(p string, attr fsproto.Attr) (*itemRecord, *reincarnationTicket) {
	saved := a.beginReincarnationOwnerLocked(nil)
	rec := a.registerLocked(p, attr)
	return rec, a.endReincarnationOwnerLocked(saved)
}

// recordReincarnationDebtLocked books one alias's refresh against the current
// owner. Callers hold a.mu.
func (a *attach) recordReincarnationDebtLocked(alias string) {
	if a.reincarnatedAliases == nil {
		a.reincarnatedAliases = map[string]*aliasReconcileState{}
	}
	st := a.reincarnatedAliases[alias]
	if st == nil {
		st = &aliasReconcileState{settled: make(chan struct{})}
		a.reincarnatedAliases[alias] = st
	}
	st.needGen++
	// OPENING THE DEBT AND RETIRING THE OBSERVATION ARE ONE EVENT.
	//
	// The debt says "this alias's cached attributes predate a reincarnation".
	// Leaving those attributes reachable while saying so is the whole hole:
	// another publisher's getattr(alias) between here and the reconciliation
	// gets a cache hit, and a cache hit is served without any authority round
	// trip, without any observation to gate, and — before publication admission
	// existed — with an inert ticket that settled instantly. It published the
	// pre-reincarnation snapshot beside the post-reincarnation identity, which
	// is the impossible attribute pair this whole file exists to prevent.
	//
	// The eviction used to live in settleAliasDebt, which is the wrong place by
	// construction: that runs with a.mu RELEASED, so the window between opening
	// the debt and evicting the observation was exactly the window a competing
	// publisher fits into. Under a.mu, with the bump, there is no such window.
	//
	// a.vol is read directly rather than through volOrErr because that helper
	// takes a.mu, which this caller already holds. A detached or unattached
	// mount has no cache to retire and nothing to publish from it either.
	if a.vol != nil {
		a.vol.AttrCache.Evict(alias)
	}
	if !a.reincarnationArmed {
		// Unowned debt. Every registration that can displace a pathname is
		// armed by its publisher, so reaching here means a new call site was
		// added without one — the debt is still RECORDED (a later ticket for the
		// same alias will settle it), but nothing is obliged to pay it now, and
		// that is a correctness gap, not a style issue. Say so loudly rather
		// than letting it be discovered as an impossible attribute pair.
		log.Printf("portablefsd: attach %s recorded unowned reincarnation debt for %q",
			a.ref, alias)
		return
	}
	if a.reincarnationOwner == nil {
		a.reincarnationOwner = &reincarnationTicket{a: a}
	}
	a.reincarnationOwner.requireLocked(alias, st.needGen)
}

// admitPublicationLocked is PUBLICATION ADMISSION for one pathname, and it runs
// on every registration that could put that pathname's attributes in front of an
// application. Callers hold a.mu.
//
// ── WHY REGISTERING OVER AN INDEBTED ALIAS IS ITSELF AN EVENT ───────────────
//
// Outstanding debt on an alias is a statement that the newest thing the daemon
// holds for it is known to predate a reincarnation. A publisher that registers
// its own observation of that alias is therefore doing one of two things, and
// the daemon cannot tell which:
//
//   - it read AFTER the debt opened, so its observation is post-reincarnation
//     and installing it is exactly right;
//   - it read BEFORE the debt opened — a cache hit taken a moment earlier, an
//     authority round trip already in flight — so its observation is the very
//     snapshot the debt exists to retire, and it has just written it into the
//     registry and is about to expose it.
//
// Nothing on either observation orders them: a plain getattr carries no version
// the daemon can compare, which is why the alias needed a debt rather than a
// version floor in the first place.
//
// So the publisher does not JOIN the outstanding generation — it MINTS A NEW
// ONE. Joining is not enough and the difference is not academic: a runner that
// completes between the competing read and this registration would satisfy the
// joined generation with a refresh that happened BEFORE the stale value was
// written, and the publisher would then re-read its own stale write and call it
// reconciled. A fresh generation forces a refresh that is ordered strictly after
// this registration, so whatever this publisher just wrote is overwritten by an
// authority observation taken later than it, and the publisher's reply carries
// that.
//
// The cost is one authority round trip for a publisher that touches an alias
// with reconciliation outstanding — a state that lasts exactly as long as one
// refresh, on the rare path where a peer replaced a hard-linked name.
func (a *attach) admitPublicationLocked(p string) {
	if a.reincarnationSettling {
		// The reconciliation's own install. See beginReincarnationSettleLocked.
		return
	}
	st := a.reincarnatedAliases[p]
	if st == nil || st.doneGen >= st.needGen {
		return
	}
	a.recordReincarnationDebtLocked(p)
}

// requireLocked adds one (alias, generation) obligation. Callers hold a.mu.
func (t *reincarnationTicket) requireLocked(alias string, gen uint64) {
	if t.need == nil {
		t.need = map[string]uint64{}
	}
	if have, ok := t.need[alias]; !ok || gen > have {
		t.need[alias] = gen
	}
}

// owes reports whether this ticket carries an obligation for alias.
func (t *reincarnationTicket) owes(alias string) bool {
	if t == nil {
		return false
	}
	t.a.mu.RLock()
	defer t.a.mu.RUnlock()
	_, ok := t.need[alias]
	return ok
}

// debtOutstanding reports whether any unsettled reconciliation work remains for
// alias. It is the observable form of "this publisher must not publish yet".
func (a *attach) debtOutstanding(alias string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	st := a.reincarnatedAliases[alias]
	return st != nil && st.doneGen < st.needGen
}

// settle discharges every obligation this ticket owns, and must complete before
// the owning publisher's reply leaves. It returns a darwin errno: a non-zero
// answer means the publisher MUST fail rather than publish, and the debt stays
// recorded for the next publisher to retry.
//
// A nil (inert) ticket settles instantly, which is the whole point of minting
// one per registration rather than draining a shared bag.
//
// reconciled reports that this ticket owned at least one obligation, which is
// exactly the condition under which the publisher's OWN pre-settle attribute
// snapshot may be older than the registry it just repaired. The publisher must
// answer from the registry in that case; see attach.reconciledAttr.
func (t *reincarnationTicket) settle(
	ctx context.Context, vol *clientcore.Volume,
) (eno int32, reconciled bool) {
	if t == nil || len(t.need) == 0 {
		return 0, false
	}
	reconciled = true
	a := t.a
	// The budget is per-alias, not per-loop-iteration, because a coalesced
	// waiter consumes an iteration without doing any work of its own.
	budget := (len(t.need) + 1) * reincarnationSettleAttempts
	for {
		alias, want, ok := a.nextUnsettledDebt(t)
		if !ok {
			return 0, reconciled
		}
		if budget <= 0 {
			log.Printf("portablefsd: attach %s could not settle reincarnation debt for %q",
				a.ref, alias)
			return darwinEIO, reconciled
		}
		budget--
		if eno := a.settleAliasDebt(ctx, vol, t, alias, want); eno != 0 {
			return eno, reconciled
		}
	}
}

// reconciledAttr is the ORDERING BARRIER between a reconciliation and the reply
// that waited for it.
//
// A publisher that settled a non-inert ticket has just paid for an alias whose
// retained snapshot was known to be stale, and the payment installed a strictly
// later authority observation into the registry. Its own `attr` variable is the
// snapshot it read on the way in — which, on the interleaving publication
// admission exists to catch, is the pre-reincarnation one. Answering from it
// would put the exact value the debt retired back in front of the application,
// having just gone to the authority to establish that it was wrong.
//
// So the reply is answered from the record. That is not a fallback and it is
// never worse: the registry is the mount's attribute store, the publisher's own
// registration wrote `attr` into it a moment ago, and anything that has moved it
// since is by construction newer. fallback covers the record having been
// detached (a second reincarnation) in the meantime, where there is nothing
// newer to answer from and the caller's own snapshot is all that exists.
func (a *attach) reconciledAttr(rec *itemRecord, fallback fsproto.Attr) fsproto.Attr {
	if rec == nil {
		return fallback
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if current := a.paths[rec.path]; current != nil && current.item == rec.item {
		return current.attr
	}
	if current := a.items[rec.item.ItemID]; current != nil {
		return current.attr
	}
	return fallback
}

// nextUnsettledDebt picks this ticket's lowest-named outstanding obligation and
// prunes the ones already discharged. Deterministic order keeps two publishers
// contending for the same aliases from ping-ponging between them.
func (a *attach) nextUnsettledDebt(t *reincarnationTicket) (string, uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var (
		best    string
		bestGen uint64
		found   bool
	)
	for alias, want := range t.need {
		st := a.reincarnatedAliases[alias]
		if st == nil || st.doneGen >= want {
			delete(t.need, alias)
			continue
		}
		if !found || alias < best {
			best, bestGen, found = alias, want, true
		}
	}
	return best, bestGen, found
}

// settleAliasDebt advances exactly one alias by one step: either it runs the
// refresh itself, or it waits for the publisher that is already running it. Both
// arms return to settle's loop, which re-evaluates rather than assuming.
func (a *attach) settleAliasDebt(
	ctx context.Context,
	vol *clientcore.Volume,
	t *reincarnationTicket,
	alias string,
	want uint64,
) int32 {
	a.mu.Lock()
	st := a.reincarnatedAliases[alias]
	if st == nil || st.doneGen >= want {
		a.mu.Unlock()
		return 0
	}
	if st.running {
		// COALESCE. Another publisher owns debt for this same alias and is
		// already off refreshing it. Wait for that attempt to COMPLETE — not for
		// it to succeed — then let the loop re-read doneGen. This is what
		// replaces the old take-all: neither publisher proceeds blind, and only
		// one RPC is issued.
		settled := st.settled
		a.mu.Unlock()
		select {
		case <-settled:
			return 0
		case <-ctx.Done():
			// The operation that owes this debt is being abandoned. Leave the
			// debt recorded and interrupt: EINTR is honest about "no answer was
			// produced" and cannot be mistaken for a published reply.
			return darwinEINTR
		}
	}
	st.running = true
	attempt := st.needGen
	rec := a.paths[alias]
	live := rec != nil
	var (
		state    *clientcore.NodeState
		fromHost bool
	)
	hostBacking := a.localFS != nil
	if live {
		state = rec.state
		// The refresh SOURCE follows current routing, not the record's stale
		// provenance flag: a grafted alias is backed by a real host inode and
		// the authority knows nothing about it.
		fromHost = rec.graft || a.localDirForLocked(alias) != ""
	}
	a.mu.Unlock()

	var (
		attr    fsproto.Attr
		obs     clientcore.AttrObservation
		install bool
		eno     int32
	)
	switch {
	case !live:
		// The alias name no longer has a record at all — it was itself detached
		// (a second reincarnation, a reclaim, a graft provenance transition)
		// while this debt was outstanding. There is no retained snapshot left to
		// contradict the replacement, so the debt IS discharged. The next
		// resolution of that name publishes a fresh identity from scratch.
	case fromHost && !hostBacking:
		// A grafted alias with no open backing root. Same rule as a missing
		// authority: retain and fail rather than publish past it.
		eno = darwinEIO
	case fromHost:
		// A graft alias's refresh source is the host inode. Its attributes never
		// travelled through the authority's version namespace, so there is no
		// version gate to run and nothing that can arrive out of order: the
		// host's stat(2) IS the newest statement about the file.
		attr, eno = a.statLocal(alias)
		switch {
		case eno == 0:
			install = true
		case eno == darwinENOENT:
			// A definite absence answers the question the debt asked. Treat it
			// as discharged and clear the errno: the name is gone, so no stale
			// snapshot of it can be observed beside the replacement.
			eno = 0
		}
	case vol == nil:
		// An authority-backed alias with no attached authority cannot be
		// restated. Retain the debt and fail rather than publish a replacement
		// beside an alias we could not refresh.
		eno = darwinEIO
	default:
		// Guarantee the RPC path: a cache hit here would restate exactly the
		// pre-replacement snapshot the debt exists to retire.
		vol.AttrCache.Evict(alias)
		var status clientcore.Status
		attr, status, obs = vol.GetattrObserved(ctx, alias, state)
		if a.testLookupAfterVolume != nil {
			a.testLookupAfterVolume(alias)
		}
		switch {
		case status == fsproto.OK:
			install = true
		case status == fsproto.ENOENT:
			// As above: a definite negative discharges the debt.
		default:
			// A transient authority failure. The debt is RETAINED (the state
			// entry is untouched below) and the publishing operation fails.
			// Publishing anyway is the one option that is never acceptable: it
			// is what puts the impossible attribute pair in front of the
			// application, and it is silent when it does.
			eno = toDarwinErr(status)
			if eno == 0 {
				eno = darwinEIO
			}
		}
	}

	a.mu.Lock()
	settled := eno == 0
	if install {
		// Arm the ticket across the install so that a reincarnation THIS refresh
		// discovers joins the same ticket instead of becoming an orphan the
		// take-all could never see. The settling arm additionally exempts this
		// one registration from publication admission — it IS the payment, not
		// another publisher arriving over unsettled state.
		saved := a.beginReincarnationSettleLocked(t)
		if fromHost {
			a.registerLocalLocked(alias, attr)
		} else {
			// THE GATE. InstallOK re-runs the mount's own monotonicity /
			// generation / fence check ATOMICALLY with the install. Installing
			// past it would be the daemon registry (the mount's SECOND
			// authoritative attribute store) travelling backwards behind the
			// caches' backs, which is exactly what postattrs.go routes every
			// mutation's post-op attributes through this same gate to prevent.
			//
			// ── A REFUSAL IS NOT A PAYMENT ──────────────────────────────────
			//
			// Its verdict used to be discarded, and the debt was settled from
			// `eno == 0` alone — that is, from the RPC having succeeded, which
			// says nothing about whether anything was installed. The
			// justification was that a refusal proves a strictly newer
			// observation already owns the path's version floor, so the
			// reconciliation had already happened by something fresher.
			//
			// That is true of exactly one of the four ways PublishOKToken
			// refuses, and not even fully of that one:
			//
			//   - v < state.version. The VERSION CACHE has moved past this
			//     observation. But the version cache is not the daemon registry,
			//     and this debt is about the registry: whoever advanced the floor
			//     may never have touched itemRecord.attr at all.
			//   - token.fenceSeq < fence. A delegation ownership boundary was
			//     installed after this read began. Nothing was published by it.
			//   - token.genEpoch != c.genEpoch. A generation epoch moved, which
			//     WIPES every retained version. Strictly less is known than
			//     before, not more.
			//   - g != c.gen. The reply belongs to a generation the cache is no
			//     longer anchored to. It is discarded, not superseded.
			//
			// In every one of those the alias keeps the exact pre-reincarnation
			// snapshot in itemRecord.attr while doneGen advances and the debt is
			// deleted — the stale value made permanent by the machinery that
			// exists to retire it.
			//
			// So the verdict is load-bearing: a refusal leaves the debt
			// OUTSTANDING and the settle loop resamples with a fresh token (the
			// eviction above guarantees a real round trip), until an install
			// succeeds, a definite absence proves the question moot, or the
			// per-alias budget runs out and the publishing operation fails
			// rather than publishing past it.
			settled = vol.InstallOK(alias, obs, func() { a.registerLocked(alias, attr) })
		}
		a.endReincarnationOwnerLocked(saved)
	}
	st.running = false
	close(st.settled)
	st.settled = make(chan struct{})
	if settled {
		if attempt > st.doneGen {
			st.doneGen = attempt
		}
		if st.doneGen >= st.needGen {
			delete(a.reincarnatedAliases, alias)
		}
	}
	a.mu.Unlock()
	return eno
}
