//go:build linux

package fusev3

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
)

// A closed operation must stay outside the cohort until recovery or terminal
// teardown. Use cancellation only after proving that it has not answered.
func closedWorkspaceCall(t *testing.T, m *Mount, call func() fuse.Status) fuse.Status {
	t.Helper()
	done := make(chan fuse.Status, 1)
	go func() { done <- call() }()
	select {
	case status := <-done:
		t.Fatalf("closed request answered before recovery or terminal teardown: %v", status)
	case <-time.After(20 * time.Millisecond):
	}
	m.cancel()
	select {
	case status := <-done:
		return status
	case <-time.After(time.Second):
		t.Fatal("terminal teardown did not release admission waiter")
		return fuse.EIO
	}
}

func TestWorkspaceClosedRequestsWaitOutsideColdCut(t *testing.T) {
	for _, fast := range []bool{false, true} {
		t.Run(map[bool]string{true: "cached-entry", false: "callback"}[fast], func(t *testing.T) {
			f, gate, _ := coldFixture(t)
			f.lookup(t, 1, "warm")
			serial := gate.Close(1)
			unique := f.unique.Add(2)
			done := make(chan fuse.Status, 1)
			go func() {
				if fast {
					done <- f.mount.workspaceFS().Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "warm", &fuse.EntryOut{})
				} else {
					_, finish, status := f.raw.mutationContext(unique)
					finish()
					done <- status
				}
			}()
			select {
			case status := <-done:
				t.Fatalf("closed request completed: %v", status)
			case <-time.After(25 * time.Millisecond):
			}
			f.raw.mu.RLock()
			count := len(f.raw.replyPublications)
			f.raw.mu.RUnlock()
			if count != 0 {
				t.Fatal("waiter entered physical drain cohort", count)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
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
				if status != fuse.OK {
					t.Fatal(status)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			f.raw.ReplyWritten(unique, fuse.EIO)
		})
	}
}

func TestWorkspaceClosedWaitEndsWithTerminalCause(t *testing.T) {
	f, gate, _ := coldFixture(t)
	gate.Close(1)
	done := make(chan error, 1)
	go func() { done <- f.mount.awaitWorkspaceServing(t.Context()) }()
	f.mount.cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal waiter remained parked")
	}
}

func TestWorkspaceClosedRequestRemainsInterruptible(t *testing.T) {
	f, gate, _ := coldFixture(t)
	gate.Close(1)
	interrupted := make(chan struct{})
	done := make(chan fuse.Status, 1)
	unique := f.unique.Add(2)
	go func() {
		done <- f.mount.workspaceFS().Lookup(interrupted, &fuse.InHeader{Unique: unique, NodeId: 1}, "cancelled", &fuse.EntryOut{})
	}()
	close(interrupted)
	select {
	case status := <-done:
		if status != fuse.Status(syscall.EINTR) {
			t.Fatal(status)
		}
	case <-time.After(time.Second):
		t.Fatal("interrupted request remained parked")
	}
	if f.raw.ReplyWriteTracked(unique) {
		t.Fatal("interrupted waiter owned a physical reply")
	}
}
