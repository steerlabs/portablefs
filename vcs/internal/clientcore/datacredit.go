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
// The proof chain, entirely between named constants:
//
//	(1) writeback.noProgressWindow      = 30s   the watchdog's verdict window
//	(2) writeback.creditWaitCap         =  5s   one AcquireDataCredit call
//	(3) creditAdmissionBudget           = 40s   this constant
//	(4) clientcore.volumeBarrierTimeout = 60s   one fsync/unmount drain attempt
//	(5) the FSKit / FUSE operation ceiling     ~60s and 120s respectively
//
//	(1) + (2) = 35s  <  (3) = 40s
//	    A genuinely stalled uplink is DECLARED stalled strictly before this
//	    budget can expire. An acquisition call still running when the watchdog's
//	    window closes reaches its own cap within one creditWaitCap of it, and
//	    that cap consults the watchdog — which by then holds the verdict. So the
//	    budget can never be the thing that reports a stall; the watchdog is, and
//	    the frontend only relays it.
//
//	(3) = 40s  <  (4) = 60s  and  <  (5)
//	    The budget and the reply it produces both land inside every enclosing
//	    bound: the barrier a concurrent fsync/unmount is running under, and the
//	    kernel's own ceiling on the operation it is waiting for. On Linux/FUSE
//	    an uninterruptible request past hung_task_timeout_secs becomes a kernel
//	    log incident; on macOS/FSKit the reply holds the extension's write
//	    callback and the kernel's vnode open for its whole duration.
//
// Reaching the budget therefore means one specific thing: the uplink made
// durable progress inside the last window, and this write still collected no
// delegated credit. The truthful answer to that is not an error at all — it is
// the OTHER lane. The authority lane consumes no stream budget, so it is
// admitted immediately, and the write SUCCEEDS rather than failing an
// application over a queue it lost.
const creditAdmissionBudget = 40 * time.Second

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

	path = cleanVolumePath(path)
	if n != nil && v.isHardlink(n) {
		// A path-keyed overlay cannot safely buffer two independently
		// discovered aliases of one inode, so a hard link is authority-only.
		// It is the one identity lane that still needs a delegation release:
		// the inode may be spelled under several scopes and every one of them
		// must leave delegated mode before the write. admitAuthorityLane
		// releases exactly that set (hardlinkMutationPaths) out here, so the
		// release inside the locks has nothing left to drain.
		return v.admitAuthorityLane(ctx, path, n, want)
	}
	if v.authorityOnlyByIdentity(path, n) {
		// Identity, not pathname, decides this. An orphaned inode is addressed
		// by inode and its former path may still be covered; a hard link cannot
		// be buffered by a path-keyed overlay at all; a pathless detached
		// handle has no scope to delegate. Each is authority-only BY
		// CONSTRUCTION, so charging it would make a write that can never
		// produce a stream byte wait — and, at the budget, fail — for credit it
		// does not need and cannot use.
		return writeback.WithResolvedLane(ctx, writeback.LaneAuthority), want, noop, nil
	}
	if forceAuthority {
		return v.admitAuthorityLane(ctx, path, n, want)
	}

	// Resolve the delegated lane, paying any transition it needs out here.
	delegated, err := v.wb.PrepareDelegatedWrite(ctx, path, int64(want))
	if err != nil {
		return ctx, 0, noop, err
	}
	if !delegated {
		return v.admitAuthorityLane(ctx, path, n, want)
	}
	return v.admitDelegatedLane(ctx, path, n, want)
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
	path string,
	n *NodeState,
	want int,
) (context.Context, int, func(), error) {
	noop := func() {}
	admitCtx, cancel := context.WithTimeout(ctx, creditAdmissionBudget)
	defer cancel()
	for {
		granted, err := v.wb.AcquireDataCredit(admitCtx, want)
		if granted > 0 {
			opCtx := writeback.WithResolvedLane(
				writeback.WithDataCredit(ctx, granted), writeback.LaneDelegated)
			return opCtx, granted, func() { v.ReleaseDataCredit(opCtx) }, nil
		}
		switch {
		case err == nil:
			// Zero credit with a healthy uplink: the link is simply sparser
			// than one wait cap. The queue is FIFO, so continuing to wait is
			// continuing to advance. Keep pacing.
		case errors.Is(err, writeback.ErrUplinkStalled):
			// The engine's watchdog, relayed unchanged. This is the only stall
			// the frontend ever reports.
			return ctx, 0, noop, err
		case admitCtx.Err() != nil && ctx.Err() == nil:
			// The admission budget expired, not the caller's context.
			return v.admitAuthorityLane(ctx, path, n, want)
		default:
			return ctx, 0, noop, err
		}
		if ctx.Err() != nil {
			return ctx, 0, noop, ctx.Err()
		}
		if admitCtx.Err() != nil {
			return v.admitAuthorityLane(ctx, path, n, want)
		}
	}
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
// What it deliberately does NOT do is hold the delegation-transition claim
// across the frontend's locks. That would make the answer immune to a
// concurrent acquisition, but it would also invert the lock order: metadata
// mutations take a.nsMu.RLock and THEN the claim, so an operation holding the
// claim while waiting for a.nsMu behind a pending writer closes a cycle. A
// deadlock is a worse outcome than the residue it would remove — and the
// residue is small and bounded: a grant that reinstalls in the window between
// this release and the write is one another writer has only just acquired, so
// the release inside beginAuthorityMutation drains at most what that writer put
// in it, never an accumulated backlog.
func (v *Volume) admitAuthorityLane(
	ctx context.Context,
	path string,
	n *NodeState,
	want int,
) (context.Context, int, func(), error) {
	noop := func() {}
	var nodes []*NodeState
	if n != nil {
		nodes = []*NodeState{n}
	}
	if err := v.wb.ReleaseFor(ctx, v.hardlinkMutationPaths(nodes, path)...); err != nil {
		return ctx, 0, noop, err
	}
	return writeback.WithResolvedLane(ctx, writeback.LaneAuthority), want, noop, nil
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
