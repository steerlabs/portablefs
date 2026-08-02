package portablefsd

// ── ROUND 17, FINDING 1: A TIMED-OUT PUBLISHING MUTATION COMMITTED INVISIBLY ─
//
// The interleaving, end to end, and every step of it is ordinary:
//
//	1. a publishing mutation request reaches the daemon and stalls;
//	2. the extension's request-local deadline expires. timeoutRequest removes
//	   the entry from `pending` and fails THAT REQUEST with a timeout;
//	3. the framework callback finishes — reporting failure — and
//	   completePublications sends the operation's PublicationAck. It has a
//	   ticket to send: the collector binds the operation when the ID is STAMPED
//	   on the request, not when a reply arrives;
//	4. the daemon's handler was never cancelled and is under no total bound. It
//	   COMMITS the mutation and exposes its publishing reply;
//	5. markPublicationReplyExposed sees ackPending and installs no publication
//	   pin — correctly, because the acknowledgement has been spent;
//	6. the frame goes out and the extension DROPS it: the request ID is no
//	   longer in `pending`.
//
// Net, before the fix: the application observed failure, the mutation happened,
// and NOTHING in the daemon was left holding the fact that the kernel's cached
// view of the affected scopes had not been updated. Step 5 did not merely
// decline to pin — it discarded the obligation.
//
// The fix is a debt rather than a deadline (see frontendRequestDeadline for why
// no advertised number can close this): the late exposure is recorded, and when
// the operation retires the scopes it touched are invalidated and exactly
// refreshed through the mount, exactly as the disconnect path repairs a
// publication whose acknowledgement was lost.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// newLatePublicationAttach builds the smallest attach that can OBSERVE a
// kernel repair: a registry holding one item, an event subscriber (that is how
// an invalidation reaches the extension), and a stubbed refresh syscall so the
// repair's exact pass never touches a real mount path.
//
// The attach carries its OWN cancellable lifetime, and the repair goroutine the
// debt spawns is bounded by it. That is deliberately not done by compressing
// the package-level repair budgets: those are read by every repair goroutine in
// the binary, including ones an earlier test leaked, so writing them from a
// test body is a genuine data race rather than a harness detail.
func newLatePublicationAttach(t *testing.T) (*attach, *itemRecord, *eventSubscriber) {
	t.Helper()
	a := newMetadataTestAttach()
	a.ref = "late-publication-attach"
	a.mountPath = "/unused-test-mount"
	a.subscribers = map[*eventSubscriber]struct{}{}
	a.localVersions = map[string]uint64{}
	a.conns = map[interface{ Close() error }]struct{}{}
	a.lifeCtx, a.lifeCancel = context.WithCancel(context.Background())
	t.Cleanup(a.lifeCancel)
	rec := a.bindTestRecord(&itemRecord{
		item: pfslocal.Item{ItemID: 5150, ItemGeneration: 1},
		path: "d/f",
		attr: fsproto.Attr{Kind: "file", Size: 7},
	})
	stubRefreshSyscall(a)
	sub := a.subscribe(0)
	t.Cleanup(func() { a.unsubscribe(sub) })
	return a, rec, sub
}

// awaitInvalidation waits for an Invalidation event naming item, which is the
// observable form of "the daemon told the kernel to stop believing what it
// holds for this scope".
func awaitInvalidation(sub *eventSubscriber, item uint64, within time.Duration) bool {
	deadline := time.After(within)
	for {
		select {
		case ev := <-sub.ch:
			inv, ok := ev.Kind.(*pfslocal.Invalidation)
			if ok && inv.Item.ItemID == item {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// TestPublishingReplyExposedAfterItsAckOwesAKernelRepair is the finding, at its
// smallest, driven through the exact frontend state machine the live shape
// reaches.
func TestPublishingReplyExposedAfterItsAckOwesAKernelRepair(t *testing.T) {
	a, rec, sub := newLatePublicationAttach(t)
	conn := &frontendConn{}

	const operationID uint64 = 9001
	_, participant, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatalf("begin logical operation: %v", err)
	}
	participant.op.paths = []string{rec.path}

	// STEP 3. The extension timed the request out, the callback finished, and
	// its acknowledgement arrives while this daemon's handler is still running.
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("the daemon refused an acknowledgement that arrived before its " +
			"reply was exposed; that is the ordinary timed-out-callback order")
	}

	// STEP 4/5. The handler commits and exposes its publishing reply into an
	// operation whose acknowledgement has already been spent.
	if !conn.markPublicationReplyExposed(operationID) {
		t.Fatal("exposing a publishing reply after the acknowledgement was refused")
	}

	// STEP 6. The handler exits; the operation retires.
	a.finishFrontendParticipant(participant)
	conn.finishLogicalRequest(operationID)

	if !awaitInvalidation(sub, rec.item.ItemID, 5*time.Second) {
		t.Fatal(
			"a publishing reply was exposed AFTER its operation had been " +
				"acknowledged — so the frontend callback was over and could not " +
				"install it — and the daemon recorded no obligation at all.\n" +
				"The mutation committed, the application was told it failed, and " +
				"the kernel is left holding a view of the scope that nothing in " +
				"this daemon will ever contradict. The acknowledgement resolves " +
				"the FRONTEND's cache; it says nothing about the KERNEL's, which " +
				"outlives every callback and every connection.",
		)
	}
}

// TestOrdinaryPublicationOrderOwesNoLateRepair is the other side of the same
// gate, and it is what keeps the fix from being a blanket invalidation of every
// operation the mount runs.
//
// The normal order — expose the reply, THEN receive the acknowledgement — is a
// complete proof that the frontend installed or discarded the published state.
// It owes nothing, and issuing a repair for it would invalidate the kernel's
// cache on every single publishing operation.
func TestOrdinaryPublicationOrderOwesNoLateRepair(t *testing.T) {
	a, rec, sub := newLatePublicationAttach(t)
	conn := &frontendConn{}

	const operationID uint64 = 9002
	_, participant, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatalf("begin logical operation: %v", err)
	}
	participant.op.paths = []string{rec.path}

	exposeTestLogicalOperation(t, conn, operationID)
	a.finishFrontendParticipant(participant)
	conn.finishLogicalRequest(operationID)
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("the acknowledgement for an exposed reply was refused")
	}

	if awaitInvalidation(sub, rec.item.ItemID, 500*time.Millisecond) {
		t.Fatal(
			"an ordinary expose-then-acknowledge operation issued a kernel " +
				"repair: every publishing operation on the mount would invalidate " +
				"the very cache it just filled",
		)
	}
}

// TestLatePublicationDebtSurvivesTheConnectionDying closes the other retirement
// order. A late exposure is ACKNOWLEDGED, so the disconnect path's
// exposed-and-unacknowledged test does not see it — and the debt would be lost
// precisely when the frontend is least able to repair anything itself.
func TestLatePublicationDebtSurvivesTheConnectionDying(t *testing.T) {
	a, rec, sub := newLatePublicationAttach(t)
	server, client := net.Pipe()
	defer client.Close()
	conn := &frontendConn{conn: server}
	if !conn.setAttach(a) {
		t.Fatal("attaching the test connection failed")
	}

	const operationID uint64 = 9003
	_, participant, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatalf("begin logical operation: %v", err)
	}
	participant.op.paths = []string{rec.path}

	if !conn.acknowledgePublication(operationID) {
		t.Fatal("early acknowledgement refused")
	}
	if !conn.markPublicationReplyExposed(operationID) {
		t.Fatal("late exposure refused")
	}
	// The connection dies before the operation's last request retires.
	a.finishFrontendParticipant(participant)
	conn.close()

	if !awaitInvalidation(sub, rec.item.ItemID, 5*time.Second) {
		t.Fatal(
			"a late publication's repair obligation was dropped when the " +
				"connection closed: the disconnect path only looks for " +
				"exposed-and-UNACKNOWLEDGED publications, and this one is " +
				"acknowledged",
		)
	}
}
