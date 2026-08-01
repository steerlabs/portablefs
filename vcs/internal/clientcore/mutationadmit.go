package clientcore

// The pre-lock mutation classifier, and the one global lock order it
// establishes.
//
// ── THE LOCK ORDER ──────────────────────────────────────────────────────────
//
//	delegation transition claim  →  frontend namespace lock (a.nsMu)
//	                             →  handle / inode locks
//	                             →  engine e.mu  →  WAL w.mu
//
// Every path-bearing mutation — data AND metadata — takes its transition claim
// HERE, before the frontend touches a single lock. Under any frontend lock the
// transition state may only be CHECKED, never waited on, never re-derived, and
// never drained through; a check that fails unwinds with all locks released and
// re-enters this file.
//
// Why the order has to be global. Before this file, the two sides took the same
// two locks in opposite orders:
//
//	writes:    (pre-lock release, no claim) → a.nsMu.RLock → claim + release
//	metadata:  a.nsMu.RLock → claim + release
//
// so an authority-lane write could reach writeLocked holding a.nsMu.RLock and a
// handle lock, then block in beginAuthorityMutation waiting for a concurrent
// acquisition's claim — an authority round trip — and, once that acquisition
// installed its grant, DRAIN that fresh grant, all under the frontend's locks.
// Go's RWMutex is writer-preferring, so the next rename, remove or delegation
// reclaim parked behind it and every lookup, getattr and read behind THAT: one
// slow uplink became a namespace-wide stall.
//
// Holding the claim across the frontend locks was previously rejected because
// it inverted the order against metadata mutations and closed a cycle. That
// objection is exactly why the order must be GLOBAL rather than per-lane: with
// every path-bearing transition admitted ahead of a.nsMu, nothing that holds
// a.nsMu ever waits for a claim, so there is no cycle to close — and the claim
// held across the locks makes the classifier's answer immune to the acquisition
// race it used to lose, which is what lets the locked region be a pure check.
//
// ── THE OPERATION DEADLINE ──────────────────────────────────────────────────
//
// One absolute deadline covers the WHOLE admission-plus-execution path:
// classification, credit or metadata backpressure, the delegation release, and
// the authority RPC that follows. Before it, each stage carried its own budget
// and they COMPOSED: a 40s credit budget could expire and then start a fresh
// unbounded release, so a healthy-but-slow uplink could hold one write for 65s+
// under a 60s kernel ceiling. A per-stage bound is not a bound on the operation.

import (
	"context"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// operationAdmissionBudget is THE bound on one frontend mutation: a single
// absolute deadline established before the first lock and carried through
// every stage that follows.
//
// The chain it has to sit inside, entirely between named constants:
//
//	(1) writeback.noProgressWindow      = 30s   the watchdog's verdict window
//	(2) writeback.creditWaitCap         =  5s   one acquisition call's wait
//	(3) creditAdmissionBudget           = 40s   the credit stage's own budget
//	(4) operationAdmissionBudget        = 50s   THIS constant
//	(5) clientcore.volumeBarrierTimeout = 60s   one fsync/unmount drain attempt
//	(6) the FSKit / FUSE operation ceiling     ~60s and 120s respectively
//
//	(1) + (2) = 35s  <  (3) = 40s  <  (4) = 50s  <  (5) = 60s  <=  (6)
//
// (3) < (4) is what makes the credit stage's expiry survivable: when a write
// stops waiting for delegated credit and diverts to the authority lane, the
// release that diversion needs runs under the SAME deadline, so prepare +
// credit + release + RPC cannot compose past (4). Previously the diversion
// started a fresh, unbounded drain — and the drain's own construction bound is
// creditDrainTarget (25s), so 40s + 25s = 65s could be spent under a 60s
// ceiling on a mount whose uplink was healthy the whole time.
//
// (1) + (2) < (3) still holds and is still worth keeping — it is what makes a
// stall verdict AVAILABLE within the credit stage's budget in the common case —
// but it does NOT prove the verdict at expiry, and nothing here may rely on it
// doing so. flusher.advance resets lastProgress on every watermark advance, so
// an advance at t39 followed by a stall pushes the earliest possible declaration
// to ~t69 while the budget still expires at t40. Budget expiry is therefore a
// statement about the WAIT, not about the far end.
//
// The classification comes from the live verdict instead: both admission gates
// consult writeback.Engine.StallVerdict at expiry, relay ErrUplinkStalled when
// it says stalled, and take their definite bounded outcome when it does not.
//
// (4) < (5) and (4) <= (6): the reply lands inside the barrier a concurrent
// fsync/unmount is running under and inside the kernel's own ceiling on the
// operation it is waiting for. Reaching (4) is a DEFINITE outcome (the caller's
// deadline, surfaced as an interrupted operation), never an unbounded wait.
//
// A var so failure-shape tests compress it; production never changes it.
var operationAdmissionBudget = 50 * time.Second

// OperationAdmissionBudget publishes the single absolute bound one frontend
// mutation runs under, so the composition proof above is a test rather than a
// comment — including from the frontends, which live in other packages and are
// where the bound has to be INSTALLED.
func OperationAdmissionBudget() time.Duration { return operationAdmissionBudget }

// WithOperationDeadline installs the operation's single absolute deadline on a
// frontend request context. A frontend whose handler can UNWIND and re-classify
// must call it once, outside its unwind loop: every pass then shares one bound,
// so the loop terminates on the deadline rather than on a pass count, and an
// operation that keeps losing a race to concurrent renames reaches a definite
// interrupted outcome inside the kernel's own ceiling instead of spinning.
//
// It is idempotent — a classifier that runs again inside the loop finds an
// earlier deadline and does not extend it.
func WithOperationDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	return withOperationDeadline(ctx)
}

// withOperationDeadline installs the operation's single absolute deadline,
// unless the caller already carries an earlier one. It is idempotent: a
// classifier that runs twice (the unwind's second pass) does not extend the
// operation's bound.
func withOperationDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(operationAdmissionBudget)
	if existing, ok := ctx.Deadline(); ok && !existing.After(deadline) {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, deadline)
}

// transitionToken is the classifier's held claim: the proof, carried into the
// locked region, that this operation owns the delegation transition for its
// exact operand set and that no grant can install underneath it.
//
// It is what turns beginAuthorityMutation from a step that could BLOCK and
// DRAIN under the frontend's locks into a pure coverage check.
type transitionToken struct {
	claim   *delegationTransitionClaim
	guard   *exclusionRelease
	targets delegationTransitionTargets
}

// covers reports whether this token's exclusion protects the operand set the
// operation actually reached under its locks, folding in any identity the
// classifier could not see.
//
// The two halves of a target set are covered differently, because they are
// protected by different things:
//
//   - PATHS are covered by the RELEASE. The classifier released every
//     delegation overlapping the token's own paths before the frontend took a
//     lock; a path the token never saw may still be covered by a grant, and
//     reaching the authority lane for it would need another release — the drain
//     the locked region must never take. So path coverage is exact membership,
//     and a path outside it is ErrLaneChanged. In practice this only widens when
//     a hard-linked inode reveals an alias spelling the index did not hold at
//     classification time, or a rename moved an operand under the frontend's
//     nose.
//
//   - IDENTITIES are covered by the CLAIM, and a claim can absorb one more
//     inode without any I/O at all. Frontends legitimately know different node
//     sets at different depths — the daemon classifies from its item registry,
//     clientcore's rename knows both endpoints' NodeStates — so the identity
//     set widens on essentially every operation and must not cost an unwind.
//     The claim is extended NON-BLOCKING: it succeeds unless an acquisition is
//     already active over that identity, and that failure is the unwind.
func (t *transitionToken) covers(paths []string, inos []uint64) bool {
	if t == nil {
		return false
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		found := false
		for _, held := range t.targets.paths {
			if held == p {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	var missing []uint64
	for _, ino := range inos {
		if ino == 0 {
			continue
		}
		if _, ok := t.targets.inos[ino]; !ok {
			missing = append(missing, ino)
		}
	}
	if len(missing) == 0 {
		return true
	}
	if !t.claim.tryExtend(nil, missing) {
		return false
	}
	for _, ino := range missing {
		t.targets.inos[ino] = struct{}{}
	}
	return true
}

type transitionTokenKey struct{}

func withTransitionToken(ctx context.Context, t *transitionToken) context.Context {
	return context.WithValue(ctx, transitionTokenKey{}, t)
}

func transitionTokenOf(ctx context.Context) *transitionToken {
	t, _ := ctx.Value(transitionTokenKey{}).(*transitionToken)
	return t
}

// MutationIntent names what a namespace mutation IS, independently of the
// pathnames it happens to touch.
//
// It exists because path coverage is not a complete classifier. A delegation
// answers the question "is this name inside a grant I hold?", and for most
// mutations that is the whole question. For four of them it is not: link(2),
// unlink-while-open, rename over an open destination, and setattr on a
// hard-linked inode are AUTHORITY-ONLY BY SEMANTICS — the handler will divert to
// the write-through lane no matter what any grant says, because one inode may be
// spelled under several delegation scopes (link, hardlink setattr) or because the
// orphan protocol cannot run inside a held grant (unlink/rename-over an open
// target).
//
// Classifying those from path coverage alone produced LaneDelegated, and the
// handler then discovered the diversion INSIDE the frontend's namespace and name
// locks and released the covering delegations there — draining an unshipped tail
// through an already-behind uplink while holding the namespace. That is the exact
// stall the pre-lock classifier exists to remove, reached by a semantic route
// instead of a path one. The intent closes it: the diversion is decided out here,
// where the release costs one operation instead of the mount.
type MutationKind uint8

const (
	// MutationOther is a mutation with no semantic diversion: its lane follows
	// from path coverage alone.
	MutationOther MutationKind = iota
	// MutationLink is link(2). Always authority-only.
	MutationLink
	// MutationUnlink is unlink(2) on a non-directory.
	MutationUnlink
	// MutationRename is rename(2).
	MutationRename
	// MutationSetattr is setattr/truncate/chmod/chown/utimes/chflags.
	MutationSetattr
)

// MutationIntent is one operation's semantics plus the ROLES of the nodes it
// addresses. The roles are load-bearing: an open handle on a rename's
// DESTINATION selects the orphan protocol, while an open handle on its SOURCE is
// entirely ordinary, and a classifier that could not tell them apart would force
// every rename of an open file onto the authority lane.
type MutationIntent struct {
	Kind MutationKind
	// Target is the node whose state the semantics turn on: the subject of a
	// setattr, the name an unlink removes, the name a rename REPLACES.
	Target *NodeState
	// Source is a rename's source. It matters only for hard-link identity and
	// for the two-names-for-one-inode no-op.
	Source *NodeState
}

// semanticAuthorityLane reports whether this operation can ONLY run on the
// authority lane, decided from what it is and from the state of the nodes it
// addresses — never from pathnames.
//
// Every arm mirrors a diversion the handler itself performs, and mirrors it
// EXACTLY. Keeping the two in agreement is the point in both directions:
// whatever the handler would discover under its locks is discovered here
// instead, and nothing the handler would have left on the delegated lane is
// dragged off it — an over-eager arm does not stall the namespace, but it does
// silently disable write-back for a whole class of operation.
func (v *Volume) semanticAuthorityLane(intent MutationIntent) bool {
	switch intent.Kind {
	case MutationLink:
		// Volume.Link releases every scope covering either end unconditionally,
		// and it must: one hard-linked inode may span delegation scopes, so the
		// link has to order after the released state. That is a fact about
		// link(2), not about what this mount's alias index happens to know yet —
		// the very first link on an nlink==1 file is exactly the case the index
		// cannot predict.
		return true
	case MutationUnlink:
		// Volume.Remove: a hard-linked inode spans scopes, and unlink-while-open
		// needs the orphan protocol, which never runs inside a held delegation.
		return v.isHardlink(intent.Target) || openWriteThroughTarget(intent.Target)
	case MutationRename:
		// Volume.Rename, arm for arm: either endpoint hard-linked, both names
		// already denoting one inode (a POSIX no-op the authority adjudicates),
		// or an open DESTINATION, which is the orphan protocol again. An open
		// SOURCE is not a diversion — the handler does not treat it as one, and
		// treating it as one here would push every rename of an open file off the
		// write-back lane.
		return v.isHardlink(intent.Source) ||
			v.isHardlink(intent.Target) ||
			sameAuthorityIdentity(intent.Source, intent.Target) ||
			openWriteThroughTarget(intent.Target)
	case MutationSetattr:
		// Volume.Setattr: an orphan is addressed by inode and routed to the
		// orphan lane; a hard-linked inode spans scopes.
		return intent.Target.Orphan() != 0 || v.isHardlink(intent.Target)
	default:
		return false
	}
}

// openWriteThroughTarget reports the node state that forces the orphan protocol:
// a live open handle on an inode that has not already been orphaned.
func openWriteThroughTarget(n *NodeState) bool {
	if n == nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.nopen > 0 && n.orphanIno.Load() == 0
}

// AdmitMutation is the pre-lock classifier for a path-bearing NAMESPACE
// mutation: create, mkdir, symlink, link, unlink, rmdir, rename, setattr,
// truncate, setxattr, removexattr.
//
// Callers MUST invoke it BEFORE taking any namespace, inode or handle lock,
// MUST pass the returned context to the operation, and MUST call settle on
// every exit path. It is the metadata twin of AdmitWrite and does the same four
// things, in the same place, holding nothing:
//
//  1. Installs the operation's single absolute deadline (see
//     operationAdmissionBudget).
//  2. Resolves the lane, holding nothing: PrepareDelegatedMutation performs
//     whatever transition the delegated lane needs — a push-down drain, or an
//     acquisition over an authority round trip.
//  3. On the DELEGATED lane, waits for METADATA-LANE admission — the namespace
//     lane's backpressure. A healthy advancing stream that has filled the
//     metadata reserve paces the mutation here instead of failing it with an
//     instant EIO under the locks; ErrUplinkStalled comes only from the engine's
//     watchdog. The authority lane writes no stream bytes and is never paced.
//  4. On the AUTHORITY lane, takes the delegation TRANSITION CLAIM for the
//     operation's complete operand set — every spelling of a hard-linked inode
//     included — releases every operand under it, and holds the claim through
//     the locked mutation, so no acquisition can install a grant underneath the
//     operation. Either way the locked region performs no transition at all.
//
// The order of 2 and 4 is load-bearing: an acquisition needs the acquire side of
// the same gate the claim holds, so claiming first and asking for a grant second
// would block on itself until the operation deadline.
//
// forceAuthority terminates an unwind: the authority lane is resolved
// unconditionally, and that lane is not a claim about a grant, so a recall has
// nothing left to invalidate. Two passes, and the second one terminates.
func (v *Volume) AdmitMutation(
	ctx context.Context,
	intent MutationIntent,
	nodes []*NodeState,
	forceAuthority bool,
	operands ...string,
) (context.Context, func(), error) {
	opCtx, cancelDeadline := withOperationDeadline(ctx)

	// STEP 0 — the SEMANTIC diversions, decided before path coverage is even
	// consulted. link/unlink-while-open/rename-over-open/hardlink-setattr end up
	// on the authority lane whatever any grant says, so asking whether a grant
	// covers them is asking the wrong question — and answering LaneDelegated to
	// it is what pushed the resulting release under the frontend's locks.
	semanticAuthority := v.semanticAuthorityLane(intent)

	// STEP 1 — decide the lane, holding NOTHING.
	//
	// This must happen before the transition claim, not after. Reaching the
	// delegated lane can require ACQUIRING a grant, and an acquisition takes the
	// acquire side of the same gate the authority claim holds — so a classifier
	// that claimed first and asked for a grant second would block on itself
	// until the operation deadline. Deciding first is also what makes the claim
	// meaningful: it is taken for the lane the operation will actually run on.
	if v.wb != nil && !forceAuthority && !semanticAuthority {
		primary, touched := splitMutationOperands(
			v.hardlinkMutationPaths(nodes, operands...),
		)
		delegated, err := v.wb.PrepareDelegatedMutation(opCtx, primary, touched...)
		if err != nil {
			cancelDeadline()
			return ctx, func() {}, err
		}
		if delegated {
			// STEP 2a — the namespace lane's BACKPRESSURE, taken here and
			// nowhere else, and taken ONLY on the lane that consumes stream
			// bytes. An authority-lane namespace mutation writes nothing to the
			// WAL, so pacing it would throttle an operation that is not
			// responsible for the backlog and cannot help drain it — the same
			// reason LaneAuthority is never credit-charged on the data plane.
			if err := v.wb.AdmitMetadataMutation(opCtx); err != nil {
				cancelDeadline()
				return ctx, func() {}, err
			}
			// Every operand is covered by one retained grant. The engine
			// acknowledges the mutation locally and never reaches
			// beginAuthorityMutation, so there is no locked-region transition to
			// protect and no claim to hold. If the grant is gone by the time the
			// mutation arrives, the engine answers ErrLaneChanged and the
			// frontend unwinds to here.
			return writeback.WithResolvedLane(opCtx, writeback.LaneDelegated),
				func() { cancelDeadline() }, nil
		}
	}

	// STEP 2 — the authority lane: claim, then release.
	//
	// The claim is taken BEFORE the release and held through the locked
	// mutation, so no acquisition can install a grant in the window the release
	// opens. That window is the whole of finding 1: without the claim, a
	// concurrent acquire could win it, and the operation — already inside
	// a.nsMu — would have to wait for that acquisition and then drain its grant.
	token, paths, endToken, err := v.beginTransitionToken(opCtx, nodes, operands...)
	if err != nil {
		cancelDeadline()
		return ctx, func() {}, err
	}
	settle := func() {
		endToken()
		cancelDeadline()
	}
	if v.wb != nil {
		if err := v.wb.ReleaseFor(opCtx, paths...); err != nil {
			settle()
			return ctx, func() {}, err
		}
	}
	return writeback.WithResolvedLane(
		withTransitionToken(opCtx, token), writeback.LaneAuthority,
	), settle, nil
}

// beginTransitionToken takes this operation's delegation transition claim and
// wraps it in a token, WITHOUT deciding a lane and without releasing anything.
// It is the step both classifiers share: the data lane's authority resolution
// (admitAuthorityLane) and the namespace lane's (AdmitMutation).
//
// The wait for the claim happens here — with NO frontend lock held, which is
// the entire reason this step was hoisted out of beginAuthorityMutation. It
// returns the token, the operand paths the claim covers, and the settle that
// hands the claim back.
func (v *Volume) beginTransitionToken(
	ctx context.Context,
	nodes []*NodeState,
	operands ...string,
) (*transitionToken, []string, func(), error) {
	paths, inos := v.hardlinkMutationTargets(nodes, operands...)
	// A conflicting active claim can be a remote acquire resolver mid-RPC, so
	// admission into the transition gate is an authority-bound wait: the
	// caller's publication must suspend while it queues, or a reciprocal
	// cross-client acquire/mutation pair deadlocks the handoff drain.
	resumeAdmission := v.suspendAuthorityPublication(ctx)
	claim, err := v.delegationTransitions.begin(ctx, authorityTransition, paths, inos)
	resumeAdmission()
	if err != nil {
		return nil, nil, nil, err
	}
	// Re-snapshot after admission. A grant that completed before this claim
	// published every reply alias first; a still-running disjoint acquire must
	// promote its reply identities against this claim and will be released
	// rather than installed on collision.
	paths, inos = v.hardlinkMutationTargets(nodes, operands...)
	resumeExtend := v.suspendAuthorityPublication(ctx)
	extendErr := claim.extend(ctx, paths, inos)
	resumeExtend()
	if extendErr != nil {
		claim.end()
		return nil, nil, nil, extendErr
	}
	guard := newExclusionRelease(claim.end)
	token := &transitionToken{
		claim:   claim,
		guard:   guard,
		targets: makeDelegationTransitionTargets(paths, inos),
	}
	return token, paths, guard.end, nil
}

// splitMutationOperands names the operand whose governing scope decides the
// lane. The FIRST operand is the mutation's own subject (the created name, the
// removed name, a rename's source); the rest are the other paths it binds.
func splitMutationOperands(paths []string) (string, []string) {
	if len(paths) == 0 {
		return "", nil
	}
	return paths[0], paths[1:]
}

// MutationAdmissionStatus maps a pre-lock mutation-admission error to the
// POSIX-visible class every frontend must agree on. It is deliberately the same
// mapping the data lane uses (DataCreditStatus): ENOSPC means "this local store
// can never fit the operation"; a far end that stopped answering is EIO-class;
// a lane that changed is an unwind, not an error.
func MutationAdmissionStatus(err error) Status {
	return DataCreditStatus(err)
}
