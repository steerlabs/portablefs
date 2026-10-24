//go:build linux

package fusev3

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
)

func TestWorkspaceUnacceptedWriteSurvivesCloseAfterCallbackAdmission(t *testing.T) {
	f, gate, _ := coldFixture(t)
	item := f.lookup(t, 1, "warm")
	opened := openDelegatedWriter(t, f, item.NodeId)
	id, _ := delegationIdentity(f.raw.nodesByID[item.NodeId].identity[:])
	state := f.mount.delegations.retainState(id, false)
	defer f.mount.delegations.releaseState(state)
	state.operation.Lock()
	locked := true
	defer func() {
		if locked {
			state.operation.Unlock()
		}
	}()
	unique := f.unique.Add(2)
	done := make(chan fuse.Status, 1)
	go func() {
		count, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: item.NodeId}, Fh: opened.Fh, Size: 3, Flags: syscall.O_RDWR}, []byte("new"))
		if status.Ok() && count != 3 {
			done <- fuse.EIO
			return
		}
		done <- status
	}()
	waitUntil(t, time.Second, "callback admitted before Close", func() bool {
		f.raw.mu.RLock()
		defer f.raw.mu.RUnlock()
		p := f.raw.replyPublications[unique]
		return p != nil && p.callbackOwned
	})
	serial := gate.Close(1)
	cut := f.mount.workspaceFS().captureWorkspaceReplies()
	state.operation.Unlock()
	locked = false
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := cut.wait(ctx); err != nil {
		t.Fatal("unaccepted waiter retained the old physical cohort", err)
	}
	if f.raw.ReplyWriteTracked(unique) || f.mount.delegations.buf.Stats().Entries != 0 {
		t.Fatal("unaccepted request escaped the cut")
	}
	select {
	case status := <-done:
		t.Fatal("unaccepted write failed instead of awaiting recovery", status)
	default:
	}
	o, err := f.mount.SuspendWorkspace(ctx, 1, serial, continuous.Time().Add(time.Second))
	if err != nil || !o.ColdComplete {
		t.Fatal("waiter blocked cold drain", o, err)
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
	if loss := f.mount.delegations.LossSequence(); loss != 0 {
		t.Fatal("unaccepted request counted as loss", loss)
	}
}

func TestWorkspaceUnacceptedWriteRetiresOnlyNoEffectSource(t *testing.T) {
	for _, effect := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-accepted-bytes", true: "filesystem-post-state"}[effect], func(t *testing.T) {
			f, gate, _ := coldFixture(t)
			item := f.lookup(t, 1, "warm")
			record := f.raw.nodesByID[item.NodeId]
			unique := f.unique.Add(2)
			ctx, finish, status := f.raw.mutationContext(unique)
			if !status.Ok() {
				t.Fatal(status)
			}
			sourceGate, err := itemSourceGate(record.node.item, true)
			if err != nil {
				t.Fatal(err)
			}
			callback := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
			lease, err := callback.acquireSource(ctx, f.raw, sourceGate)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.markAssigned(); err != nil {
				t.Fatal(err)
			}
			gate.Close(1)
			lease.resolveAllNoBinding()
			if err := lease.markDefiniteNoChange(); err != nil {
				t.Fatal(err)
			}
			finish()
			if effect {
				f.raw.mu.Lock()
				callback.publication.postState = &authoritypb.PostState{}
				f.raw.mu.Unlock()
			}
			cut := f.mount.workspaceFS().captureWorkspaceReplies()
			err = f.raw.retireUnacceptedWorkspaceWrite(unique)
			if effect {
				if err == nil || !f.raw.ReplyWriteTracked(unique) || lease.released {
					t.Fatal("effect owner was retired", err)
				}
				return
			}
			if err != nil || !lease.released || f.raw.ReplyWriteTracked(unique) {
				t.Fatal("no-effect source remained in old cut", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := cut.wait(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
