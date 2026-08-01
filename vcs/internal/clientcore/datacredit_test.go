package clientcore

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestAdmitWriteWithoutAnEngineIsAFullInstantGrant covers the mount shapes that
// have no write-back engine at all. There is no bounded WAL to protect, so
// classification must cost nothing and grant everything: a frontend that paused
// on a mount with no journal would be inventing back pressure out of thin air.
func TestAdmitWriteWithoutAnEngineIsAFullInstantGrant(t *testing.T) {
	v := &Volume{}
	ctx := context.Background()
	start := time.Now()
	opCtx, granted, settle, err := v.AdmitWrite(ctx, "d/f", nil, 4<<20, false)
	defer settle()
	if err != nil {
		t.Fatalf("classify with no engine: %v", err)
	}
	if granted != 4<<20 {
		t.Fatalf("granted %d of %d with no engine", granted, 4<<20)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("classify with no engine took %v", elapsed)
	}
	// Nothing was charged, so nothing must be refundable: a grant that was
	// never taken from a ledger must not decrement one on the way out.
	if left := writeback.ReclaimDataCredit(opCtx); left != 0 {
		t.Fatalf("an uncharged grant left %d refundable bytes on the ctx", left)
	}
	v.ReleaseDataCredit(opCtx) // must not panic on a nil engine
}

// TestAdmitWriteIgnoresEmptyWrites keeps the zero-length case off every slow
// path: no ledger traffic, no ctx allocation, no delegation probe.
func TestAdmitWriteIgnoresEmptyWrites(t *testing.T) {
	v := &Volume{}
	opCtx, granted, settle, err := v.AdmitWrite(context.Background(), "d/f", nil, 0, false)
	defer settle()
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

// TestLaneChangeIsAnUnwindSignalAndNeverAnErrno keeps the internal signal
// internal. If it ever mapped to a POSIX class an application would be handed a
// failure for a write that was not attempted at all.
func TestLaneChangeIsAnUnwindSignalAndNeverAnErrno(t *testing.T) {
	st := statusErr(writeback.ErrLaneChanged)
	if !LaneChanged(st) {
		t.Fatalf("statusErr(ErrLaneChanged) = %d; frontends cannot recognise the unwind", st)
	}
	if st == fsproto.EIO || st == fsproto.ENOSPC || st == fsproto.OK {
		t.Fatalf("the unwind signal collides with the POSIX outcome %d", st)
	}
	if LaneChanged(fsproto.EIO) || LaneChanged(fsproto.OK) || LaneChanged(statusExactRetry) {
		t.Fatal("LaneChanged accepted a status that is not the unwind signal")
	}
	if got := DataCreditStatus(writeback.ErrLaneChanged); !LaneChanged(got) {
		t.Fatalf("DataCreditStatus(ErrLaneChanged) = %d, want the unwind signal", got)
	}
}

// TestCreditAdmissionBudgetProofChain checks the constant's argument rather
// than trusting its prose. Two inequalities carry the whole design:
//
//	noProgressWindow + creditWaitCap < creditAdmissionBudget
//	    The watchdog's stall verdict always lands STRICTLY BEFORE the budget
//	    expires, so the budget can never be the thing that reports a stall.
//	    Without this the frontend would synthesise ErrUplinkStalled for a link
//	    the engine considers perfectly healthy, and an application would see EIO
//	    on a mount that is merely slow.
//
//	creditAdmissionBudget < volumeBarrierTimeout
//	    The budget and the reply it produces both land inside the bound on the
//	    operation the kernel is actually waiting for.
func TestCreditAdmissionBudgetProofChain(t *testing.T) {
	verdict := writeback.NoProgressWindow() + writeback.CreditWaitCap()
	if creditAdmissionBudget <= verdict {
		t.Fatalf("admission budget %v does not exceed the watchdog verdict bound %v "+
			"(noProgressWindow %v + creditWaitCap %v); the frontend would time out "+
			"before the engine could tell it whether the uplink is actually stalled",
			creditAdmissionBudget, verdict,
			writeback.NoProgressWindow(), writeback.CreditWaitCap())
	}
	if creditAdmissionBudget >= volumeBarrierTimeout {
		t.Fatalf("admission budget %v is not under the %v barrier bound",
			creditAdmissionBudget, volumeBarrierTimeout)
	}
}
