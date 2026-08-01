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
// (1) + (2) < (3) is unchanged and still load-bearing: a genuinely stalled
// uplink is DECLARED stalled by the watchdog strictly before the credit budget
// can expire, so the diversion — whose release would drain into a dead far end
// — is never reached on a stalled link. The frontend relays the watchdog's
// verdict instead.
//
// (4) < (5) and (4) <= (6): the reply lands inside the barrier a concurrent
// fsync/unmount is running under and inside the kernel's own ceiling on the
// operation it is waiting for. Reaching (4) is a DEFINITE outcome (the caller's
// deadline, surfaced as an interrupted operation), never an unbounded wait.
//
// A var so failure-shape tests compress it; production never changes it.
var operationAdmissionBudget = 50 * time.Second

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
	nodes []*NodeState,
	forceAuthority bool,
	operands ...string,
) (context.Context, func(), error) {
	opCtx, cancelDeadline := withOperationDeadline(ctx)

	// STEP 1 — decide the lane, holding NOTHING.
	//
	// This must happen before the transition claim, not after. Reaching the
	// delegated lane can require ACQUIRING a grant, and an acquisition takes the
	// acquire side of the same gate the authority claim holds — so a classifier
	// that claimed first and asked for a grant second would block on itself
	// until the operation deadline. Deciding first is also what makes the claim
	// meaningful: it is taken for the lane the operation will actually run on.
	if v.wb != nil && !forceAuthority {
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
