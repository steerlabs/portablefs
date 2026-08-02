package clientcore

// The pre-lock write classifier.
//
// Every real frontend holds something while it writes: the daemon calls in under
// a.nsMu.RLock, FUSE under the kernel's per-inode serialization. Go's RWMutex is
// writer-preferring, so anything that blocks while holding the read side queues
// the next nsMu.Lock — a rename, a remove, a delegation reclaim — and every
// lookup, getattr and read that arrives after it. One slow uplink becomes a
// whole-namespace stall on paths that have nothing to do with the backlog. That
// is the incident geometry this file removes.
//
// Three things in a write can block for an unbounded time, and all three are
// resolved HERE, before the frontend takes a single lock:
//
//  1. The delegation transition. Reaching the delegated lane can require pushing
//     an ancestor grant down — draining its whole unshipped tail through the
//     uplink that is already behind, then releasing it durably — or acquiring a
//     grant over an authority round trip. Reaching the authority lane can
//     require releasing whatever covers the path: the same drain.
//  2. The credit wait. Bulk data admission is paced against the measured
//     authority-applied rate, so a saturated lane parks the writer.
//  3. The identity question. An orphaned inode, a hard link and a pathless
//     detached handle are authority-only BY CONSTRUCTION, and none of that is
//     visible from a pathname.
//
// What crosses into the locked region is therefore not a hint but a decided
// answer, and the engine's job in there is to CHECK it, never to re-derive it.
// When the answer no longer holds the engine says so (writeback.ErrLaneChanged)
// and the operation unwinds to here — it never transitions under the caller's
// locks.

import (
	"context"
	"errors"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// creditAdmissionBudget bounds the TOTAL time one write spends in pre-lock
// data-lane admission before it stops waiting for delegated credit and takes
// the authority lane instead.
//
// It is NOT a stall detector, and that is the point. The engine already owns
// exactly one stall verdict — the flusher's no-progress watchdog — and a
// frontend that invents a second one lies: writeback.AcquireDataCredit returns
// (0, nil) precisely when the watchdog has NOT declared a stall, so converting
// that into ErrUplinkStalled reports a dead far end for a link that is merely
// slower than one wait cap. An application then sees EIO on a healthy mount.
//
// It used to claim its own arithmetic PROVED the verdict:
//
//	writeback.noProgressWindow (30s) + writeback.creditWaitCap (5s) = 35s < 40s
//
// read as "a genuinely stalled uplink is DECLARED stalled strictly before this
// budget can expire", which made expiry mean "healthy but slow" and licensed an
// unconditional divert to the authority lane. It proves no such thing. The
// watchdog's window runs from the last WATERMARK ADVANCE — the flusher resets it
// on every advance — not from the moment this write began to wait. A write that
// parks at t0 and sees the authority advance at t39 reaches 40s with the
// watchdog unable to declare before ~t69, so expiry is SILENT about the far end.
// It therefore no longer licenses anything: the expiry arm asks
// writeback.Engine.StallVerdict for the live verdict, and a stalled one is
// relayed as ErrUplinkStalled rather than diverting a release-and-RPC into a far
// end that is applying nothing (see divertAfterCreditBudget).
//
// What this constant still carries is the BOUND, and the bound is what composes:
//
//	(1) creditAdmissionBudget               = 40s   this budget
//	(2) clientcore.operationAdmissionBudget = 50s   ONE mutation's deadline
//	(3) clientcore.volumeBarrierTimeout     = 60s   one fsync/unmount drain
//	(4) the FSKit / FUSE operation ceiling        ~60s and 120s respectively
//
//	(1) < (2) < (3) <= (4)
//	    The credit stage is a SUB-deadline of the operation's, so whatever it
//	    leaves over is exactly what the authority-lane diversion and the release
//	    it needs run inside — they cannot compose past (2). And the reply lands
//	    inside the barrier a concurrent fsync/unmount is running under and inside
//	    the kernel's own ceiling on the operation it is waiting for. On
//	    Linux/FUSE an uninterruptible request past hung_task_timeout_secs becomes
//	    a kernel log incident; on macOS/FSKit the reply holds the extension's
//	    write callback and the kernel's vnode open for its whole duration.
//
// Reaching the budget therefore means one specific thing, and only it: this
// write collected no delegated credit inside the bound. Whether the far end is
// alive is a separate question with a separate owner — and when the answer is
// yes, it is not an error at all but the OTHER lane, which consumes no stream
// budget, is admitted immediately, and lets the write SUCCEED rather than
// failing an application over a queue it lost.
//
// A var so failure-shape tests can compress it; production never changes it.
var creditAdmissionBudget = 40 * time.Second

// AdmitWrite is the pre-lock classifier. Callers MUST invoke it BEFORE taking
// any namespace, inode or handle lock, and MUST pass the returned context to
// the write and call settle on every exit path.
//
// It returns the number of bytes the caller may write NOW. A short grant is a
// normal, healthy outcome: write exactly that prefix and reply a POSIX short
// write; the kernel reissues the remainder as a fresh operation, re-classified
// from scratch. granted is never zero without an error, because a zero-length
// successful write is not a signal any kernel write path can act on.
//
// Errors:
//
//   - writeback.ErrNoSpace: the operation exceeds the data lane at any
//     occupancy. ENOSPC, and the only one this path produces.
//   - writeback.ErrUplinkStalled: the engine's watchdog declared the far end
//     dead. EIO-class. Never synthesized here.
//   - context / lifecycle errors: propagated unchanged.
//
// On every error path everything it collected has already been released, so an
// error outcome never leaks credit or holds an exclusion.
//
// forceAuthority resolves the authority lane unconditionally. It is what
// terminates an unwind: a delegated lane resolved outside the locks can be
// invalidated inside them, and reclassifying to a second delegated answer could
// be invalidated in turn. The authority lane is not a claim about a grant, so
// there is nothing left for a recall to invalidate — the write is admitted on
// the lane that consumes no stream budget at all. Two passes, and the second
// one terminates.
func (v *Volume) AdmitWrite(
	ctx context.Context,
	path string,
	n *NodeState,
	want int,
	forceAuthority bool,
) (context.Context, int, func(), error) {
	noop := func() {}
	if want <= 0 || v.wb == nil {
		// Nothing to charge, or no engine to charge it against. The lane is
		// still recorded so the engine keeps its no-transition promise.
		return writeback.WithResolvedLane(ctx, writeback.LaneAuthority), want, noop, nil
	}

	// ONE absolute deadline for the whole operation: classification, the credit
	// wait, the delegation release a lane diversion needs, and the authority RPC
	// that follows all run under it. Per-stage budgets compose; this does not.
	opCtx, cancelDeadline := withOperationDeadline(ctx)
	fail := func(err error) (context.Context, int, func(), error) {
		cancelDeadline()
		return ctx, 0, noop, err
	}

	path = cleanVolumePath(path)
	if n != nil && v.isHardlink(n) {
		// A path-keyed overlay cannot safely buffer two independently
		// discovered aliases of one inode, so a hard link is authority-only.
		// It is the one identity lane that still needs a delegation release:
		// the inode may be spelled under several scopes and every one of them
		// must leave delegated mode before the write. admitAuthorityLane
		// releases exactly that set (hardlinkMutationPaths) out here, so the
		// release inside the locks has nothing left to drain.
		return v.admitAuthorityLane(opCtx, cancelDeadline, path, n, want, writeback.DoorIdentity)
	}
	if v.authorityOnlyByIdentity(path, n) {
		// Identity, not pathname, decides this. An orphaned inode is addressed
		// by inode and its former path may still be covered; a hard link cannot
		// be buffered by a path-keyed overlay at all; a pathless detached
		// handle has no scope to delegate. Each is authority-only BY
		// CONSTRUCTION, so charging it would make a write that can never
		// produce a stream byte wait — and, at the budget, fail — for credit it
		// does not need and cannot use.
		//
		// No transition token: neither identity reaches beginAuthorityMutation
		// (Volume.Write routes an orphan to the inode-addressed lane and a
		// pathless handle to WriteExactHandle), so there is no locked-region
		// transition to protect.
		//
		// It still passes through the lane's gate. "The overlay cannot
		// represent this inode" is a statement about ROUTING; it says nothing
		// about durability, and an orphan's bytes are acknowledged out of the
		// same session, discarded by the same fence, and invisible to the same
		// WAL-derived checks as everything else on this lane.
		granted, charged, cerr := v.chargeAuthorityLane(opCtx, want, writeback.DoorIdentity)
		if cerr != nil {
			return fail(cerr)
		}
		return writeback.WithResolvedLane(charged, writeback.LaneAuthority),
			granted, func() {
				v.wb.SettleAuthorityCharge(charged)
				cancelDeadline()
			}, nil
	}
	if forceAuthority {
		// THE UNWIND'S TERMINATING SECOND PASS.
		//
		// It resolves the authority lane unconditionally, and that is correct:
		// a delegated answer could be invalidated again, and this pass must
		// terminate. What it is NOT is ungated. Resolving a lane without a
		// recall to fear is a routing guarantee; it was never an admission
		// exemption, and reading it as one is what let a saturated mount
		// convert its own backpressure into unpaced write-through — the door
		// this round exists to close.
		//
		// The pass still terminates, and for a reason that has nothing to do
		// with how long admission takes: ErrLaneChanged is produced for exactly
		// one input, a ctx resolved to LaneDelegated (writeback.admitDataBytes).
		// This pass resolves LaneAuthority, so it CANNOT be answered
		// ErrLaneChanged and cannot unwind a third time however long it waits.
		// The two-pass bound is a property of the lane, not of the speed of
		// admission.
		return v.admitAuthorityLane(opCtx, cancelDeadline, path, n, want, writeback.DoorForced)
	}

	// Resolve the delegated lane, paying any transition it needs out here.
	delegated, err := v.wb.PrepareDelegatedWrite(opCtx, path, int64(want))
	if err != nil {
		return fail(err)
	}
	if !delegated {
		return v.admitAuthorityLane(opCtx, cancelDeadline, path, n, want, writeback.DoorUncovered)
	}
	return v.admitDelegatedLane(opCtx, cancelDeadline, path, n, want)
}

// authorityOnlyByIdentity reports the lanes that follow from WHAT the node is,
// independently of any delegation state.
func (v *Volume) authorityOnlyByIdentity(path string, n *NodeState) bool {
	switch {
	case path == "":
		// A detached descriptor: the pathless exact lane, authority-only by
		// construction (Volume.WriteExactHandle).
		return true
	case n != nil && n.Orphan() != 0:
		// Unlinked-but-open. The write is addressed to the orphan inode and
		// never touches the write-back overlay, however covered its former path
		// still is.
		return true
	}
	return false
}

// admitDelegatedLane charges credit for a write whose delegated lane is proven.
// The wait happens here, holding nothing, and its outcome is definite.
func (v *Volume) admitDelegatedLane(
	ctx context.Context,
	cancelDeadline context.CancelFunc,
	path string,
	n *NodeState,
	want int,
) (context.Context, int, func(), error) {
	noop := func() {}
	fail := func(err error) (context.Context, int, func(), error) {
		cancelDeadline()
		return ctx, 0, noop, err
	}
	// The credit stage's budget is a SUB-deadline of the operation's, never an
	// independent one: whatever it leaves is what the authority-lane diversion
	// and its release have to work with, and the sum is bounded by
	// operationAdmissionBudget rather than by 40s + an unbounded drain.
	admitCtx, cancel := context.WithTimeout(ctx, creditAdmissionBudget)
	defer cancel()
	for {
		granted, err := v.wb.AcquireDataCredit(admitCtx, want)
		if granted > 0 {
			v.wb.NoteDelegatedAdmission(int64(granted))
			opCtx := writeback.WithResolvedLane(
				writeback.WithDataCredit(ctx, granted), writeback.LaneDelegated)
			return opCtx, granted, func() {
				v.ReleaseDataCredit(opCtx)
				cancelDeadline()
			}, nil
		}
		switch {
		case err == nil:
			// Zero credit with a healthy uplink: the link is simply sparser
			// than one wait cap. The queue is FIFO, so continuing to wait is
			// continuing to advance. Keep pacing.
		case errors.Is(err, writeback.ErrUplinkStalled):
			// The engine's watchdog, relayed unchanged. This is the only stall
			// the frontend ever reports.
			return fail(err)
		case admitCtx.Err() != nil && ctx.Err() == nil:
			// The credit budget expired while the operation deadline still has
			// room. Expiry bounds the wait; it does not say whether the far end
			// is alive, so ask before diverting into it.
			return v.divertAfterCreditBudget(ctx, cancelDeadline, path, n, want)
		default:
			return fail(err)
		}
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		if admitCtx.Err() != nil {
			return v.divertAfterCreditBudget(ctx, cancelDeadline, path, n, want)
		}
	}
}

// divertAfterCreditBudget is the credit stage's ONE expiry outcome, so the
// stalled-vs-slow split cannot drift between the two points the admission loop
// reaches it from.
//
// The divert itself is unchanged and still the right answer for a live uplink:
// the authority lane consumes no stream budget, and it runs under the SAME
// operation deadline, so the release it needs cannot push the operation past the
// bound. What is new is that it is no longer taken on faith. The budget's expiry
// never proved the uplink healthy (see creditAdmissionBudget), and diverting on
// a stalled one sends this write's release and RPC into a far end that is
// applying nothing. So the engine's watchdog is consulted, and a stall verdict is
// relayed unchanged — the same EIO-class answer every other lane gives for a
// dead uplink, and still the only stall this frontend ever reports.
func (v *Volume) divertAfterCreditBudget(
	ctx context.Context,
	cancelDeadline context.CancelFunc,
	path string,
	n *NodeState,
	want int,
) (context.Context, int, func(), error) {
	if v.wb.StallVerdict().Stalled {
		cancelDeadline()
		return ctx, 0, func() {}, writeback.ErrUplinkStalled
	}
	return v.admitAuthorityLane(ctx, cancelDeadline, path, n, want, writeback.DoorBudget)
}

// chargeAuthorityLane is the authority lane's admission, and the reason no lane
// is uncharged any more.
//
// It exists as its own step because the lane's two costs are paid to different
// creditors. The DELEGATION RELEASE below is paid to the frontend's locks — it
// is why this whole classifier is pre-lock. The ADMISSION CHARGE is paid to
// durability: every byte the authority acknowledges is a byte held by a session
// that a fence discards, so the mount has to bound how many of them it is
// carrying and has to be able to name them afterwards. The stream lane has
// bounded and named its bytes since the credit gate existed; this lane did
// neither, and the difference was 734 MiB nobody could account for.
//
// A short grant is normal here for exactly the reason it is normal on the other
// lane: it becomes a POSIX short write, the kernel reissues the remainder as a
// fresh operation, and the write COMPLETES paced instead of failing.
func (v *Volume) chargeAuthorityLane(
	ctx context.Context, want int, door writeback.LaneDoor,
) (int, context.Context, error) {
	// The CHOICE is recorded here and the BYTES after the gate answers: a write
	// that picks this door and is then refused took the door but admitted
	// nothing, and a tally that credited it the request's bytes would report
	// traffic that never happened.
	v.wb.NoteLaneDoorChoice(door)
	granted, err := v.wb.AdmitAuthorityBytes(ctx, int64(want))
	if err != nil {
		return 0, ctx, err
	}
	if granted <= 0 {
		// The gate's contract forbids this (zero-with-nil-error is not a signal
		// any kernel write path can act on). Treat a violation as the typed
		// condition rather than returning a success no caller can use.
		return 0, ctx, writeback.ErrAuthorityUnproven
	}
	v.wb.NoteLaneDoorAdmitted(door, granted)
	return int(granted), writeback.WithAuthorityCharge(ctx, granted), nil
}

// admitAuthorityLane resolves the authority lane and PAYS FOR IT out here: it
// releases every delegation covering the write's paths — including every other
// spelling of a hard-linked inode — before the frontend takes a single lock.
//
// This is the release beginAuthorityMutation used to take under a.nsMu.RLock,
// and it is the expensive half of the incident. Releasing a grant means
// draining its whole unshipped tail through the uplink that is already behind;
// under a writer-preferring RWMutex's read side that parks the next rename or
// reclaim and every reader behind it. Moved here it costs one operation.
//
// It also HOLDS the delegation-transition claim across the frontend's locks,
// and that is what makes the answer definite rather than a guess.
//
// Releasing without the claim left a race the previous revision documented as a
// bounded residue and it was not one: writer A's pre-lock release could find
// nothing to release, writer B could then win the acquire transition and install
// a fresh grant, and A — already inside a.nsMu.RLock and its handle lock —
// would wait for B's claim (an authority round trip) and then DRAIN B's grant,
// under the frontend's locks. The claim taken here excludes that acquisition
// entirely: between this release and the write, no grant can install.
//
// Holding the claim across the locks is only safe because the lock order is now
// GLOBAL — every path-bearing transition admission, metadata included, happens
// ahead of a.nsMu (see mutationadmit.go). Nothing that holds a.nsMu waits for a
// claim, so there is no cycle for this ordering to close.
func (v *Volume) admitAuthorityLane(
	ctx context.Context,
	cancelDeadline context.CancelFunc,
	path string,
	n *NodeState,
	want int,
	door writeback.LaneDoor,
) (context.Context, int, func(), error) {
	noop := func() {}
	// Charge FIRST, before the transition claim and the release.
	//
	// The order is load-bearing. A charge taken after the claim would hold the
	// claim — which excludes every delegation acquisition on these paths —
	// across a wait for the far end to prove its backlog, so a slow authority
	// would block delegation transitions mount-wide. Taken here the wait holds
	// nothing at all, which is the same property the delegated lane's credit
	// wait has and the same reason this classifier is pre-lock in the first
	// place.
	granted, charged, cerr := v.chargeAuthorityLane(ctx, want, door)
	if cerr != nil {
		cancelDeadline()
		return ctx, 0, noop, cerr
	}
	releaseCharge := func() { v.wb.SettleAuthorityCharge(charged) }

	var nodes []*NodeState
	if n != nil {
		nodes = []*NodeState{n}
	}
	token, paths, endToken, err := v.beginTransitionToken(charged, nodes, path)
	if err != nil {
		releaseCharge()
		cancelDeadline()
		return ctx, 0, noop, err
	}
	settle := func() {
		// The charge settles LAST: whatever the authority acknowledged was
		// recorded on this ctx by the code that ran the RPC, and settling
		// before the token is released would publish an unproven byte count
		// that a concurrent status read could see as already closed out.
		endToken()
		releaseCharge()
		cancelDeadline()
	}
	if err := v.wb.ReleaseFor(charged, paths...); err != nil {
		settle()
		return ctx, 0, noop, err
	}
	return writeback.WithResolvedLane(
		withTransitionToken(charged, token), writeback.LaneAuthority,
	), granted, settle, nil
}

// ReleaseDataCredit refunds whatever of opCtx's grant the engine never turned
// into WAL bytes. It is exactly-once and safe to call unconditionally on every
// exit path of a write, including success: a write that reached the engine has
// already had its grant consumed and settled there, and this call finds nothing
// left to give back.
//
// It is what makes the error paths honest. A frontend that classifies, charges,
// and then fails — a bad handle, a detached volume, a lane that changed — hands
// the bytes straight back, so the ledger never drifts away from the exact WAL
// reservation underneath it.
func (v *Volume) ReleaseDataCredit(opCtx context.Context) {
	n := writeback.ReclaimDataCredit(opCtx)
	if n > 0 && v.wb != nil {
		v.wb.ReleaseDataCredit(n)
	}
}

// DataCreditStatus maps a classification error to the POSIX-visible class every
// frontend must agree on. ENOSPC means "this local store can never fit the
// operation"; everything else about a far end that stopped answering is EIO.
// Confusing the two is how an application learns to delete files to fix a
// network problem.
func DataCreditStatus(err error) Status {
	switch {
	case err == nil:
		return fsproto.OK
	case errors.Is(err, writeback.ErrNoSpace):
		return fsproto.ENOSPC
	case errors.Is(err, writeback.ErrLaneChanged):
		return statusLaneRetry
	default:
		return fsproto.EIO
	}
}
