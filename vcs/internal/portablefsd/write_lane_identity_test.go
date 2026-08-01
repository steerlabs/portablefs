package portablefsd

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// Lane classification is a question about the NODE, not about a pathname.
//
// An orphaned inode, a hard link and a pathless detached handle are
// authority-only BY CONSTRUCTION: clientcore routes each of them to an
// inode-addressed or write-through lane that never touches the write-back WAL.
// A classifier that sees only a path cannot tell any of them apart from an
// ordinary delegated write, so it charges them against the data lane — and a
// charge is not free. Against a saturated lane the write queues, waits out the
// whole admission budget, and can be failed for credit it never needed and
// could not have used, all before clientcore gets to choose the lane that was
// authority-only the entire time.
//
// These tests hold the data lane at exactly its setpoint, so any charged write
// MUST queue. An identity-lane write completing promptly, with the queue never
// non-empty, is the proof it was never charged.

// orphanHandle unlinks the delegated file while its handle stays open, then
// re-establishes a delegation over the parent scope. The result is the exact
// shape the finding names: a node with a live orphan identity whose FORMER path
// the mount still delegates, so a path-only classifier sees "covered" and
// charges, while the write itself is inode-addressed and never reaches the WAL.
func orphanHandle(t *testing.T, f *writeCreditFixture) {
	t.Helper()
	ctx := context.Background()
	h := f.a.handles[delegatedHandle]
	if st := f.vol.Remove(ctx, delegatedPath, h.state); st != fsproto.OK {
		t.Fatalf("unlink %s: %d", delegatedPath, st)
	}
	if h.state.Orphan() == 0 {
		t.Skip("the fixture's unlink did not produce an orphan identity")
	}
	// The unlink released the parent grant. A sibling mutation takes it back,
	// so the orphan's former path is covered once more.
	if _, st := f.vol.Create(ctx, "d/sibling", 0o644); st != fsproto.OK {
		t.Fatalf("create sibling: %d", st)
	}
	if !f.vol.Writeback().Covers(delegatedPath) {
		t.Skip("the fixture did not re-delegate the parent scope")
	}
}

func TestOrphanedHandleWriteIsNotChargedAgainstASaturatedDataLane(t *testing.T) {
	f := newWriteCreditFixture(t)
	f.releaseLane()
	orphanHandle(t, f)
	f.holdWholeDataLane(t)

	// The lane is held at its setpoint by the fixture, so a charged write
	// queues and receives nothing for the whole admission budget.
	done := make(chan int32, 1)
	go func() {
		_, eno := admittedWrite(context.Background(), f.a, &pfslocal.WriteRequest{
			Handle: delegatedHandle,
			Data:   make([]byte, 64<<10),
		})
		done <- eno
	}()

	deadline := time.After(15 * time.Second)
	for {
		select {
		case eno := <-done:
			if eno != 0 {
				t.Fatalf("orphaned-handle write = errno %d, want success", eno)
			}
			if w := f.vol.WritebackStatus().CreditWaiters; w != 0 {
				t.Fatalf("an orphaned-handle write left %d waiters in the credit queue", w)
			}
			return
		case <-deadline:
			t.Fatal("an orphaned-handle write queued against a saturated data lane; " +
				"its lane never touches the WAL and must not be charged")
		default:
		}
		if w := f.vol.WritebackStatus().CreditWaiters; w > 0 {
			t.Fatal("an orphaned-handle write entered the credit queue; " +
				"the classifier decided its lane from the pathname, not the node")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
