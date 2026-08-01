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
	armed  bool
	ticket *reincarnationTicket
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
	saved := reincarnationOwnerScope{armed: a.reincarnationArmed, ticket: a.reincarnationOwner}
	a.reincarnationArmed, a.reincarnationOwner = true, t
	return saved
}

// endReincarnationOwnerLocked disarms and returns the ticket the enclosed
// registrations created — nil when they created no debt at all, which is the
// overwhelmingly common case and costs nothing. Callers hold a.mu.
func (a *attach) endReincarnationOwnerLocked(saved reincarnationOwnerScope) *reincarnationTicket {
	t := a.reincarnationOwner
	a.reincarnationArmed, a.reincarnationOwner = saved.armed, saved.ticket
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
func (t *reincarnationTicket) settle(ctx context.Context, vol *clientcore.Volume) int32 {
	if t == nil || len(t.need) == 0 {
		return 0
	}
	a := t.a
	// The budget is per-alias, not per-loop-iteration, because a coalesced
	// waiter consumes an iteration without doing any work of its own.
	budget := (len(t.need) + 1) * reincarnationSettleAttempts
	for {
		alias, want, ok := a.nextUnsettledDebt(t)
		if !ok {
			return 0
		}
		if budget <= 0 {
			log.Printf("portablefsd: attach %s could not settle reincarnation debt for %q",
				a.ref, alias)
			return darwinEIO
		}
		budget--
		if eno := a.settleAliasDebt(ctx, vol, t, alias, want); eno != 0 {
			return eno
		}
	}
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
		// take-all could never see.
		saved := a.beginReincarnationOwnerLocked(t)
		if fromHost {
			a.registerLocalLocked(alias, attr)
		} else {
			// THE GATE. InstallOK re-runs the mount's own monotonicity /
			// generation / fence check ATOMICALLY with the install. A refusal
			// means a strictly newer observation already owns this path's
			// version floor — so the reconciliation this debt asked for has
			// already happened, by something fresher than what we hold, and the
			// debt is discharged with the newer state left standing. Installing
			// anyway would be the daemon registry (the mount's SECOND
			// authoritative attribute store) travelling backwards behind the
			// caches' backs, which is exactly what postattrs.go routes every
			// mutation's post-op attributes through this same gate to prevent.
			vol.InstallOK(alias, obs, func() { a.registerLocked(alias, attr) })
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
