package clientcore

// Frontend-side placement of the drain-time credit wait.
//
// The engine's own write path paces internally (writeback.pacedWrite), which is
// exactly right for a caller that holds nothing. Every real frontend holds
// something: the daemon calls in under a.nsMu.RLock, FUSE under the kernel's
// per-inode serialization. A pacing wait taken there parks a shared reader for
// as long as the uplink is slow, and Go's RWMutex is writer-preferring — so one
// pending nsMu.Lock (rename, remove, delegation reclaim) queues behind the
// paced writer and every subsequent lookup/getattr/read queues behind IT. A
// single slow uplink becomes a whole-namespace stall. That is the incident
// geometry this file removes: the wait happens HERE, before any frontend lock,
// and what crosses the lock boundary is a decided answer.
//
// The surface is deliberately tiny — acquire, release — because the interesting
// part is not the API, it is the placement.

import (
	"context"
	"errors"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// frontendCreditBudget bounds the TOTAL time one frontend write operation may
// spend waiting for data-lane admission before it answers the kernel.
//
// Why a frontend budget exists at all. writeback.AcquireDataCredit is bounded
// per CALL (creditWaitCap, 5s) and can legitimately return zero bytes with a
// nil error: "the uplink is progressing, just slower than one wait cap." That
// is an invitation to keep pacing, and the engine's own lock-free path accepts
// it indefinitely. A frontend cannot: it owes the kernel an answer.
//
// Why 18 seconds.
//
//   - It is ~3.6 wait caps, so an operation gets at least three complete FIFO
//     passes through the credit queue before it is declared hopeless. A short
//     grant of even one chunk ends the wait immediately, so reaching the budget
//     means the queue produced literally nothing across all of them.
//   - It is far under every enclosing bound. clientcore's own volumeBarrierTimeout
//     is 60s (one fsync/unmount drain attempt); the credit setpoint's horizon
//     T_drain is 25s. 18s leaves better than 3x headroom under the 60s figure,
//     so a write that exhausts the budget AND its error reply both land well
//     inside the operation the kernel is waiting on.
//   - It is under the kernel-side ceilings on both frontends. On Linux/FUSE an
//     uninterruptible request past hung_task_timeout_secs (120s by default)
//     becomes a kernel-log incident and a user-visible D-state process. On
//     macOS/FSKit the daemon reply keeps the extension's write callback — and
//     the kernel's vnode — open for its whole duration. Neither platform is
//     served by a write that is still "thinking" tens of seconds later.
//
// The invariant boundary this constant draws. The engine's watchdog
// (noProgressWindow, 30s) judges DURABLE progress of the stream and is the
// right instrument for the engine. The frontend budget judges ADMISSION
// progress for ONE operation, and is deliberately shorter: an uplink whose acks
// are so sparse that a queued write collects zero bytes across 18 seconds is,
// from the kernel's point of view, indistinguishable from a stalled one.
// Frontends therefore surface the same EIO-class writeback.ErrUplinkStalled the
// engine's watchdog would eventually produce, just at the boundary where the
// answer is owed. It is never ENOSPC: the local store is not full, the far end
// is not answering, and the very next write after the uplink recovers is
// admitted normally.
const frontendCreditBudget = 18 * time.Second

// AcquireDataCredit is the frontend's pre-lock admission step for n bytes of
// bulk file data at path. Callers MUST invoke it BEFORE taking any namespace,
// inode or handle lock, and MUST pass the returned context to the write.
//
// It returns the number of bytes the caller may write NOW. A short grant
// (granted < n) is a normal, healthy outcome: write exactly that prefix and
// reply a POSIX short write. The kernel reissues the remainder as a new
// operation, which is re-paced from scratch. granted is never zero without an
// error, because a zero-length successful write is not a signal any kernel
// write path can act on (FSKit's adapter explicitly treats it as EIO).
//
// Lanes. Credit governs the DELEGATED (write-back) lane only, because that is
// the only lane whose bytes land in the bounded WAL. A write with no covering
// delegation goes write-through: it consumes no stream budget, so charging or
// pacing it would throttle a workload that is not responsible for the backlog
// and cannot help drain it. The lane is resolved here with a lock-free-ish
// Engine.Covers probe (one atomic load, then a read lock the engine never holds
// across a wait) taken before the frontend's own locks, so the decision costs
// nothing and is made in the only place where waiting is safe.
//
// Errors:
//
//   - writeback.ErrNoSpace: n exceeds the data lane at any occupancy. ENOSPC.
//   - writeback.ErrUplinkStalled: no credit at all within frontendCreditBudget,
//     or the engine's watchdog declared the far end dead. EIO-class.
//   - context / lifecycle errors: propagated unchanged.
//
// On every error path the call has already refunded whatever it collected, so
// an error outcome never leaks credit.
func (v *Volume) AcquireDataCredit(ctx context.Context, path string, n int) (context.Context, int, error) {
	if n <= 0 || v.wb == nil {
		// No engine (or nothing to charge): a full instant grant, uncharged.
		// The marker still goes on so the engine's own pre-admission keeps its
		// no-queueing promise for this operation.
		return writeback.WithFrontendPacing(ctx), n, nil
	}
	if !v.wb.Covers(cleanVolumePath(path)) {
		// Write-through lane: no WAL bytes, no charge, no wait. This is the
		// property that keeps a write-through-heavy workload at full speed while
		// a delegated flood is paced against a dead uplink.
		return writeback.WithFrontendPacing(ctx), n, nil
	}
	deadline := time.Now().Add(frontendCreditBudget)
	for {
		granted, err := v.wb.AcquireDataCredit(ctx, n)
		if err != nil {
			if granted > 0 {
				v.wb.ReleaseDataCredit(granted)
			}
			return ctx, 0, err
		}
		if granted > 0 {
			return writeback.WithFrontendPacing(writeback.WithDataCredit(ctx, granted)), granted, nil
		}
		// Zero credit, nil error: the uplink IS applying, just more sparsely
		// than one wait cap. Keep pacing until the budget says the distinction
		// has stopped mattering to the kernel.
		if err := ctx.Err(); err != nil {
			return ctx, 0, err
		}
		if !time.Now().Before(deadline) {
			return ctx, 0, writeback.ErrUplinkStalled
		}
	}
}

// ReleaseDataCredit refunds whatever of opCtx's grant the engine never turned
// into WAL bytes. It is exactly-once and safe to defer unconditionally on every
// exit path of a frontend write, including success: a write that reached the
// engine has already had its grant consumed and settled there, and this call
// finds nothing left to give back.
//
// It is what makes the error paths honest. A frontend that acquires credit and
// then fails — a bad handle, a detached volume, a diverted orphan/exact lane,
// an authority fallthrough — hands the bytes straight back, so the ledger never
// drifts away from the exact WAL reservation underneath it.
func (v *Volume) ReleaseDataCredit(opCtx context.Context) {
	n := writeback.ReclaimDataCredit(opCtx)
	if n > 0 && v.wb != nil {
		v.wb.ReleaseDataCredit(n)
	}
}

// DataCreditStatus maps a credit-acquisition error to the POSIX-visible class
// every frontend must agree on. ENOSPC means "this local store can never fit
// the operation"; everything else about a far end that stopped answering is
// EIO. Confusing the two is how an application learns to delete files to fix a
// network problem.
func DataCreditStatus(err error) Status {
	switch {
	case err == nil:
		return fsproto.OK
	case errors.Is(err, writeback.ErrNoSpace):
		return fsproto.ENOSPC
	default:
		return fsproto.EIO
	}
}
