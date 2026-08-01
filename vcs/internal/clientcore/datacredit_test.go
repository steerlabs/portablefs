package clientcore

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestAcquireDataCreditWithoutAnEngineIsAFullInstantGrant covers the mount
// shapes that have no write-back engine at all. There is no bounded WAL to
// protect, so admission must cost nothing and grant everything: a frontend that
// paused on a mount with no journal would be inventing back pressure out of
// thin air.
func TestAcquireDataCreditWithoutAnEngineIsAFullInstantGrant(t *testing.T) {
	v := &Volume{}
	ctx := context.Background()
	start := time.Now()
	opCtx, granted, err := v.AcquireDataCredit(ctx, "d/f", 4<<20)
	if err != nil {
		t.Fatalf("acquire with no engine: %v", err)
	}
	if granted != 4<<20 {
		t.Fatalf("granted %d of %d with no engine", granted, 4<<20)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("acquire with no engine took %v", elapsed)
	}
	// Nothing was charged, so nothing must be refundable: a grant that was
	// never taken from a ledger must not decrement one on the way out.
	if left := writeback.ReclaimDataCredit(opCtx); left != 0 {
		t.Fatalf("an uncharged grant left %d refundable bytes on the ctx", left)
	}
	v.ReleaseDataCredit(opCtx) // must not panic on a nil engine
}

// TestAcquireDataCreditIgnoresEmptyWrites keeps the zero-length case off every
// slow path: no ledger traffic, no ctx allocation, no probe.
func TestAcquireDataCreditIgnoresEmptyWrites(t *testing.T) {
	v := &Volume{}
	opCtx, granted, err := v.AcquireDataCredit(context.Background(), "d/f", 0)
	if err != nil || granted != 0 {
		t.Fatalf("empty write: granted=%d err=%v", granted, err)
	}
	if left := writeback.ReclaimDataCredit(opCtx); left != 0 {
		t.Fatalf("empty write carried %d bytes of credit", left)
	}
}

// TestDataCreditStatusKeepsENOSPCForTheLocalStoreOnly is the wire-status half
// of the errno contract every frontend then maps. Only an operation the data
// lane can never fit is ENOSPC; a far end that stopped answering is EIO.
func TestDataCreditStatusKeepsENOSPCForTheLocalStoreOnly(t *testing.T) {
	if got := DataCreditStatus(nil); got != fsproto.OK {
		t.Fatalf("DataCreditStatus(nil) = %d", got)
	}
	if got := DataCreditStatus(writeback.ErrNoSpace); got != fsproto.ENOSPC {
		t.Fatalf("DataCreditStatus(ErrNoSpace) = %d, want ENOSPC", got)
	}
	if got := DataCreditStatus(writeback.ErrUplinkStalled); got != fsproto.EIO {
		t.Fatalf("DataCreditStatus(ErrUplinkStalled) = %d, want EIO", got)
	}
	// And the general clientcore mapping agrees, so a stalled uplink surfaced
	// by the engine mid-write reaches the frontend as the same class.
	if got := statusErr(writeback.ErrUplinkStalled); got != fsproto.EIO {
		t.Fatalf("statusErr(ErrUplinkStalled) = %d, want EIO", got)
	}
}

// TestFrontendCreditBudgetSitsUnderEveryEnclosingBound is the constant's
// argument, checked rather than asserted in prose. It has to be several
// per-call wait caps (so an operation gets real chances at the queue) and
// comfortably under the barrier timeout that bounds the operation the kernel is
// actually waiting on.
func TestFrontendCreditBudgetSitsUnderEveryEnclosingBound(t *testing.T) {
	if frontendCreditBudget >= volumeBarrierTimeout {
		t.Fatalf("frontend budget %v is not under the %v barrier bound", frontendCreditBudget, volumeBarrierTimeout)
	}
	if frontendCreditBudget > volumeBarrierTimeout/3 {
		t.Fatalf("frontend budget %v leaves less than 3x headroom under %v", frontendCreditBudget, volumeBarrierTimeout)
	}
	if frontendCreditBudget < 15*time.Second {
		t.Fatalf("frontend budget %v is too short to give a queued write several passes at the gate", frontendCreditBudget)
	}
}
