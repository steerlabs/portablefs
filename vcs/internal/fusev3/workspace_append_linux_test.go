//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
)

func TestWorkspaceUnassignedAppendSurvivesColdCut(t *testing.T) {
	f, gate, _ := coldFixture(t)
	item := f.lookup(t, 1, "warm")
	opened := openDelegatedWriter(t, f, item.NodeId)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.raw.beforeSourceAssignment = func(l *sourcePublicationLease) {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	unique := f.unique.Add(2)
	done := make(chan fuse.Status, 1)
	go func() {
		_, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: item.NodeId}, Fh: opened.Fh, Size: 3, Flags: syscall.O_WRONLY | syscall.O_APPEND}, []byte("new"))
		done <- status
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("append did not reach assignment seam")
	}
	serial := gate.Close(1)
	cut := f.mount.workspaceFS().captureWorkspaceReplies()
	close(release)
	select {
	case status := <-done:
		t.Fatalf("unassigned append returned instead of waiting: %v; authority calls=%v", status, f.rpcCalls())
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
	for _, boundary := range []string{"independent-before-assignment", "authority-after-assignment"} {
		t.Run(boundary, func(t *testing.T) {
			f, gate, _ := coldFixture(t)
			item := f.lookup(t, 1, "warm")
			opened := openDelegatedWriter(t, f, item.NodeId)
			unique := f.unique.Add(2)
			var lease *sourcePublicationLease
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
			select {
			case status := <-done:
				if status != want || lease == nil || lease.assigned != (boundary == "authority-after-assignment") {
					t.Fatal("append erased an independent or assigned refusal", status, lease)
				}
			case <-time.After(time.Second):
				t.Fatal("failed append retried as fresh work")
			}
			completeTestReply(t, f.raw, unique, want)
		})
	}
}
