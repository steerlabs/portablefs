package portablefsd

import (
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
)

// These tests pin the recall-path lock-order invariant documented on
// onMarkOrphan: the authority recall/invalidation path must never block on a
// clientcore.NodeState mutex while it holds attach.mu.
//
// The cycle it prevents has no timeout on any edge:
//
//	frontend mutation: holds n.mu across an authority round trip whose
//	                   publication-gate resume() waits for the handoff to end
//	handoff:           cannot end until persistAssignedAuthorityIdentities
//	                   (its OnHandoffPrepared hook) takes a.mu
//	recall:            holds a.mu while waiting for that same n.mu
//
// testBeforeMarkOrphan runs at exactly the point onMarkOrphan is about to take
// a NodeState mutex, so both tests observe the real call site rather than a
// re-implementation of it.

const recallTestOrphanIno = 4242

func newRecallLockOrderAttach() (*attach, *clientcore.NodeState) {
	a := newScopeTestAttach()
	// A live authority handle whose node matches the recalled inode: the
	// open-after-rename window onMarkOrphan exists to serve.
	state := clientcore.NewNodeStateWithAuthority(9, recallTestOrphanIno)
	a.handles[1] = &handleRecord{id: 1, itemID: 9, path: "f", state: state}
	return a, state
}

// The direct invariant: attach.mu is not held at the moment the recall path
// reaches for a NodeState mutex.
func TestRecallOrphanMarkingReleasesAttachMuBeforeNodeStateLock(t *testing.T) {
	a, _ := newRecallLockOrderAttach()
	checked := false
	a.testBeforeMarkOrphan = func() {
		checked = true
		if !a.mu.TryLock() {
			t.Error("recall path still held attach.mu while about to lock a NodeState")
			return
		}
		a.mu.Unlock()
	}
	a.onMarkOrphan("f", recallTestOrphanIno)
	if !checked {
		t.Fatal("recall path never reached a NodeState: the fixture selected no target")
	}
}

// The liveness shape: with the NodeState mutex owned by a suspended frontend
// mutation, the recall must still let the delegation handoff take attach.mu
// and finish. Pre-fix, onMarkOrphan holds attach.mu across that wait and the
// three-way cycle closes; this test then times out instead of completing.
func TestRecallOrphanMarkingAdmitsHandoffAttachMu(t *testing.T) {
	a, _ := newRecallLockOrderAttach()
	handoffTookAttachMu := make(chan struct{})
	var once sync.Once
	a.testBeforeMarkOrphan = func() {
		// Stand in for the frontend mutation that owns this node's mutex
		// across an unbounded wait for the delegation handoff to complete.
		// The recall cannot take n.mu until the handoff ends, and the handoff
		// cannot end until it has taken attach.mu.
		once.Do(func() {
			go func() {
				a.mu.Lock()
				a.mu.Unlock()
				close(handoffTookAttachMu)
			}()
		})
		select {
		case <-handoffTookAttachMu:
		case <-time.After(10 * time.Second):
			t.Error("delegation handoff never acquired attach.mu")
		}
	}

	done := make(chan struct{})
	go func() {
		a.onMarkOrphan("f", recallTestOrphanIno)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("recall orphan marking wedged the delegation handoff on attach.mu")
	}
}
