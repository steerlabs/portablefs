//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
)

func TestWorkspaceUnassignedAppendSurvivesColdCut(t *testing.T) {
	for _, boundary := range []string{"subscription-sample", "source-assignment"} {
		t.Run(boundary, func(t *testing.T) { workspaceUnassignedAppendColdCut(t, boundary) })
	}
}

func workspaceUnassignedAppendColdCut(t *testing.T, boundary string) {
	f, gate, _ := coldFixture(t)
	item := f.lookup(t, 1, "warm")
	opened := openDelegatedWriter(t, f, item.NodeId)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	if boundary == "source-assignment" {
		f.raw.beforeSourceAssignment = func(l *sourcePublicationLease) {
			once.Do(func() { close(entered); <-release })
		}
	}
	var waitBulk, releaseBulk func()
	if boundary == "subscription-sample" {
		identity := f.raw.nodesByID[item.NodeId].identity
		waitBulk, releaseBulk = holdAppendBeforeSubscription(t, f.mount, identity[:])
	}
	unique := f.unique.Add(2)
	done := make(chan fuse.Status, 1)
	go func() {
		_, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: item.NodeId}, Fh: opened.Fh, Size: 3, Flags: syscall.O_WRONLY | syscall.O_APPEND}, []byte("new"))
		done <- status
	}()
	if boundary == "source-assignment" {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("append did not reach assignment seam")
		}
	} else {
		waitBulk()
	}
	serial := gate.Close(1)
	cut := f.mount.workspaceFS().captureWorkspaceReplies()
	close(release)
	if releaseBulk != nil {
		releaseBulk()
	}
	select {
	case status := <-done:
		f.rpc.mu.Lock()
		writes := len(f.rpc.writes)
		f.rpc.mu.Unlock()
		t.Fatalf("unassigned append returned instead of waiting: %v; authority WRITE count=%d", status, writes)
	case <-time.After(25 * time.Millisecond):
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := cut.wait(ctx); err != nil {
		t.Fatal("append retained the old reply cohort", err)
	}
	o, err := f.mount.SuspendWorkspace(ctx, 1, serial, continuous.Time().Add(time.Second))
	if err != nil || !o.ColdComplete {
		t.Fatal(o, err)
	}
	o, err = f.mount.RecoverWorkspace(ctx, 1, serial)
	if err != nil || !o.Prepared {
		t.Fatal(o, err)
	}
	proof, err := gate.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.Prepared(proof); err != nil {
		t.Fatal(err)
	}
	if err = gate.Open(1, serial); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-done:
		if !status.Ok() {
			t.Fatal(status, f.mount.fatalError())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	completeTestReply(t, f.raw, unique, fuse.OK)
	f.rpc.mu.Lock()
	writes := len(f.rpc.writes)
	f.rpc.mu.Unlock()
	if writes != 1 || f.mount.delegations.LossSequence() != 0 {
		t.Fatal("unassigned append duplicated or recorded as lost", writes)
	}
}

func TestWorkspaceAppendRefusalsDoNotRetry(t *testing.T) {
	for _, boundary := range []string{"subscription-unavailable", "independent-before-assignment", "authority-after-assignment"} {
		t.Run(boundary, func(t *testing.T) {
			f, gate, _ := coldFixture(t)
			item := f.lookup(t, 1, "warm")
			opened := openDelegatedWriter(t, f, item.NodeId)
			unique := f.unique.Add(2)
			var lease *sourcePublicationLease
			var waitBulk, releaseBulk func()
			if boundary == "subscription-unavailable" {
				identity := f.raw.nodesByID[item.NodeId].identity
				waitBulk, releaseBulk = holdAppendBeforeSubscription(t, f.mount, identity[:])
			}
			want := fuse.EIO
			f.raw.beforeSourceAssignment = func(l *sourcePublicationLease) {
				lease = l
				if boundary == "independent-before-assignment" {
					gate.Close(1)
					l.workspaceCheck = func() error { return errors.New("independent admission failure") }
				}
			}
			if boundary == "authority-after-assignment" {
				f.rpc.replyOverride = func(q *authoritypb.Request) (*authoritypb.Response, error) {
					if q.GetWrite() != nil {
						gate.Close(1)
						return &authoritypb.Response{Errno: int32(syscall.EIO)}, nil
					}
					return nil, nil
				}
			}
			done := make(chan fuse.Status, 1)
			go func() {
				_, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: item.NodeId}, Fh: opened.Fh, Size: 3, Flags: syscall.O_WRONLY | syscall.O_APPEND}, []byte("new"))
				done <- status
			}()
			if waitBulk != nil {
				waitBulk()
				f.mount.subscription.suspend()
				releaseBulk()
			}
			select {
			case status := <-done:
				if status != want {
					t.Fatal("append erased a definite refusal", status)
				}
				if boundary == "subscription-unavailable" {
					if lease != nil {
						t.Fatal("unavailable subscription acquired a source")
					}
				} else if lease == nil || lease.assigned != (boundary == "authority-after-assignment") {
					t.Fatal("append changed assignment ownership", lease)
				}
			case <-time.After(time.Second):
				t.Fatal("failed append retried as fresh work")
			}
			completeTestReply(t, f.raw, unique, fuse.OK)
		})
	}
}

// Occupy the existing RPC capacity seam until append owns its synchronous
// delegation slot. Closing admission here precedes subscription sampling and
// replay assignment, without introducing another product scheduling hook.
func holdAppendBeforeSubscription(t *testing.T, m *Mount, identity []byte) (func(), func()) {
	t.Helper()
	id, err := delegationIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	state := m.delegations.retainState(id, false)
	if state == nil {
		t.Fatal("append has no retained delegation")
	}
	t.Cleanup(func() { m.delegations.releaseState(state) })
	for range cap(m.bulk) {
		m.bulk <- struct{}{}
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			for range cap(m.bulk) {
				<-m.bulk
			}
		})
	}
	t.Cleanup(release)
	wait := func() {
		deadline := time.Now().Add(5 * time.Second)
		for state.operation.TryLock() {
			state.operation.Unlock()
			if time.Now().After(deadline) {
				release()
				t.Fatal("append did not reach saturated RPC lane")
			}
			time.Sleep(time.Millisecond)
		}
	}
	return wait, release
}

// Use the existing clock-owner seam to close admission between delegation's
// first acceptance check and its serving check, before OPEN can allocate.
type appendAdmissionClock struct {
	workspaceTestClockOwner
	checks atomic.Int32
	close  func()
}

func (c *appendAdmissionClock) Check(p mountenrollment.Permit) error {
	if c.checks.Add(1) == 2 && c.close != nil {
		c.close()
	}
	return c.workspaceTestClockOwner.Check(p)
}

func TestWorkspaceAppendDelegationAdmissionPreservesClosure(t *testing.T) {
	for _, closed := range []bool{true, false} {
		name := "independent-subscription"
		if closed {
			name = "gate-closed"
		}
		t.Run(name, func(t *testing.T) {
			f, gate, _ := coldFixture(t)
			item := f.lookup(t, 1, "warm")
			opened := openDelegatedWriter(t, f, item.NodeId)
			record, handle := f.raw.acquireFileHandle(opened.Fh)
			defer f.raw.releaseHandleOperation(record)
			id, err := delegationIdentity(record.inode.identity[:])
			if err != nil {
				t.Fatal(err)
			}
			state := f.mount.delegations.retainState(id, false)
			state.admission.Lock()
			state.setGrantLocked(nil)
			state.admission.Unlock()
			f.mount.delegations.releaseState(state)
			unique := f.unique.Add(2)
			ctx, finish, status := f.raw.mutationContext(unique)
			if !status.Ok() {
				t.Fatal(status)
			}
			cut := f.mount.workspaceFS().captureWorkspaceReplies()
			clock := &appendAdmissionClock{}
			want := error(syscall.EIO)
			if closed {
				clock.close = func() { gate.Close(1) }
				want = workspaceadmission.ErrClosed
			} else {
				f.mount.subscription.suspend()
			}
			f.mount.workspaceLifecycle.clock = clock
			calls := f.rpcCalls()
			err = handle.node.ensureWriteDelegation(ctx, handle)
			finish()
			if err != want || f.rpcCalls() != calls {
				completeTestReply(t, f.raw, unique, fuse.OK)
				t.Fatalf("delegation lost its exact admission refusal: got %v, want %v; authority calls before=%d after=%d", err, want, calls, f.rpcCalls())
			}
			if closed {
				if err := f.raw.retireUnacceptedWorkspaceWrite(unique); err != nil {
					t.Fatal(err)
				}
				wait, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				if err := cut.wait(wait); err != nil {
					t.Fatal(err)
				}
			} else {
				completeTestReply(t, f.raw, unique, fuse.OK)
			}
		})
	}
}
