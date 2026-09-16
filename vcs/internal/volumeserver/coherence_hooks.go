package volumeserver

import "context"

// CoherenceCommitHooks is the sequencer/handler integration boundary. Publish
// OnCommit after an ordered storage apply, while the mutation still owns its
// dependencies; then RELEASE the storage stripes and dependency turn before
// WaitWithdrawn. In a post-apply path use context.WithoutCancel(requestContext):
// cancellation must not acknowledge a commit before ack-or-horizon. A canceled
// reply may be dropped, but its replay outcome still owes the visibility wait.
// Pre-grant waits can use a cancelable context because Abort withdraws the
// reservation before any writer can buffer under it.
//
// A recall flush has a separate applied receipt: publish, release commit locks,
// DelegationFlush.End(sequence), then make the applied receipt available to the
// holder BEFORE the visibility wait. Otherwise two recalling writers can wait
// for each other's flush visibility before sending either drain acknowledgment.
// The transport must reserve service capacity for flush application and CONTROL
// acks independently of ordinary requests waiting for withdrawal or recall.
type CoherenceCommitHooks interface {
	OnCommit([]ChangeEntry) uint64
	WaitWithdrawn(context.Context, uint64, SessionID) error
}

// CoherenceDurabilityHooks is implemented by the coordinator and called by the
// fsync group. seq must be a contiguous VOLUME storage cut. The existing inode
// fsync group's appliedGeneration is not this cut; the integration stream must
// track completed per-inode generations or perform a volume barrier first.
type CoherenceDurabilityHooks interface {
	DurableSequence(uint64)
	LatestDurable() uint64
}

// CoherenceSessionHooks supplements Authority credential validation. CheckSession
// runs on each subscribed request, including reads and CONTROL acknowledgments.
// ExpireSession is the permanent runtime terminal hook (Authority.OnSessionEnd),
// not a recoverable subscription fence. It may close cache-handle accounting
// because a terminal runtime session cannot resubscribe with usable handles.
type CoherenceSessionHooks interface {
	CheckSession(SubscriptionToken) error
	ExpireSession(SessionID)
}

var (
	_ CoherenceCommitHooks     = (*CoherenceCoordinator)(nil)
	_ CoherenceDurabilityHooks = (*CoherenceCoordinator)(nil)
	_ CoherenceSessionHooks    = (*CoherenceCoordinator)(nil)
)
